use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::str::FromStr;

pub extern crate bdk;
pub extern crate bip39;
pub extern crate elements_miniscript as miniscript;
pub extern crate serde;
pub extern crate log;

use bdk::TransactionDetails;
use miniscript::bitcoin::network::constants::Network;
use miniscript::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use miniscript::elements::confidential::{
    self, Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
};
use miniscript::elements::encode::deserialize as elm_des;
use miniscript::elements::encode::serialize as elm_ser;
use miniscript::elements::secp256k1_zkp::{All, PublicKey, Secp256k1};
use miniscript::elements::slip77::MasterBlindingKey;
use miniscript::elements::TxOutSecrets;
use miniscript::elements::{Address, AddressParams};
use miniscript::{Descriptor, DescriptorPublicKey };
use miniscript::descriptor::*;

use bdk::blockchain::Blockchain;
use bdk::database::memory::MemoryDatabase;
use bdk::database::{BatchDatabase, BatchOperations, Database};
use bdk::electrum_client::{
    Client, ConfigBuilder, ElectrumApi, GetHistoryRes, ListUnspentRes, Socks5Config,
};
use serde::{Deserialize, Serialize};

use log::*;

pub enum ScriptType {
    P2shP2wpkh = 0,
    P2wpkh = 1,
    P2pkh = 2,
}

#[derive(Default,Debug)]
pub struct DownloadTxResult {
    pub txs: Vec<(elements::Txid, elements::Transaction)>,
    pub unblinds: Vec<(elements::OutPoint, elements::TxOutSecrets)>,
}

#[derive(Default,Debug,Clone)]
pub struct EDKTransactionDetails {
    pub txs: Vec<(elements::Txid, elements::Transaction, i32)>,
    pub unblinds: Vec<(elements::OutPoint, elements::TxOutSecrets, i32)>,
}

#[derive(Debug,Clone)]
pub struct EDKBalanceOutput {
    pub asset : String,
    pub txid : elements::Txid,
    pub value : u64,
    pub height : i32
}

#[derive(Debug,Clone)]
pub struct TxWithHeight{
    tx : elements::Transaction,
    tx_height : i32
}

pub struct Wallet<D> {
    descriptor: Descriptor<DescriptorPublicKey>,
    master_blinding_key: MasterBlindingKey,
    secp: Secp256k1<All>,
    client: Client,
    database: RefCell<D>,
    network: &'static AddressParams,
}

impl<D> Wallet<D>
where
    D: BatchDatabase,
{
    pub fn new(
        descriptor: Descriptor<DescriptorPublicKey>,
        master_blinding_key: MasterBlindingKey,
        database: D,
        client: Client,
        network: &'static AddressParams,
    ) -> Result<Self, bdk::Error> {
        Ok(Wallet {
            descriptor,
            master_blinding_key,
            secp: Secp256k1::new(),
            client,
            database: RefCell::new(database),
            network,
        })
    }

    /// Get the Liquid network the wallet is using.
    pub fn network(&self) -> &'static AddressParams {
        self.network
    }

    /// Return a reference to the internal blockchain client
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn get_address(&self, index: u32) -> Result<Address, bdk::Error> {
        let xpk = self
            .descriptor
            .derived_descriptor(&self.secp, index)
            .unwrap();
        let unconfidential_address = xpk.address(&self.network).unwrap();
        let script_pubkey = xpk.script_pubkey();
        let blinding_sk = self.master_blinding_key.derive_blinding_key(&script_pubkey);
        let blinding_pk = PublicKey::from_secret_key(&self.secp, &blinding_sk);
        let confidential_address = unconfidential_address.to_confidential(blinding_pk);
        Ok(confidential_address)
    }

    // Return a newly derived address using the external descriptor
    pub fn get_new_address(&self) -> Result<Address, bdk::Error> {
        let index = match self.descriptor.is_deriveable() {
            false => 0,
            true => self
                .database
                .borrow_mut()
                .increment_last_index(bdk::KeychainKind::External)?,
        };
        let addr = self.get_address(index)?;
        Ok(addr)
    }

    fn get_previous_addresses(&self) -> Result<Vec<Address>, bdk::Error> {
        let mut addresses = vec![];
        for i in 0..self
            .database
            .borrow()
            .get_last_index(bdk::KeychainKind::External)?
            .unwrap_or(0)
            + 1
        {
            addresses.push(self.get_address(i)?);
        }
        Ok(addresses)
    }

    pub fn is_mine_address(&self, addr: &Address) -> Result<bool, bdk::Error> {
        Ok(self.get_previous_addresses()?.contains(addr))
    }

    pub fn list_transactions(&self) -> Result<EDKTransactionDetails,bdk::Error> {
        let addrs: Vec<Address> = self.get_previous_addresses()?;
        Ok(self.balance_addresses_with_height(addrs)?)
        
    }

    pub fn balance(&self) -> Result<HashMap<String, u64>, bdk::Error> {
        let addrs: Vec<Address> = self.get_previous_addresses()?;
        let mut balances = HashMap::new();

        for unblind in self.balance_addresses(addrs)?.unblinds {
            info!("unblinded tx: {:?}",unblind.clone()); 
            let tx_out = unblind.1;
            *balances.entry(tx_out.asset.to_string()).or_insert(0) += tx_out.value;
        }
        Ok(balances)
    }

    pub fn balance_with_height(&self) -> Result<Vec<(String, u64,i32)>, bdk::Error> {
        let addrs: Vec<Address> = self.get_previous_addresses()?;
        let mut balances = vec![]; 
        let bawh = self.balance_addresses_with_height(addrs)?;

        for unblind in bawh.unblinds {
            let tx_out = unblind.1;
            let tx_height = unblind.2;
            balances.push((tx_out.asset.to_string(),tx_out.value,tx_height));
        }
        Ok(balances)
    }

    pub fn balance_with_txid_and_height(&self) -> Result<Vec<EDKBalanceOutput>, bdk::Error> {
        let addrs: Vec<Address> = self.get_previous_addresses()?;
        let mut balances = vec![]; 
        let bawh = self.balance_addresses_with_height(addrs)?;

        for unblind in bawh.unblinds {
            let tx_out = unblind.1;
            let tx_height = unblind.2;
            let tx_id = unblind.0.txid;
            let bal_output = EDKBalanceOutput {
                asset : tx_out.asset.to_string(),
                txid : tx_id,
                value : tx_out.value,
                height : tx_height
            };
            balances.push(bal_output);
        }
        Ok(balances)
    }

    pub fn balance_addresses_with_height(&self, addrs: Vec<Address>) -> Result<EDKTransactionDetails, bdk::Error> {
        //let client = Client::new("ssl://blockstream.info:995").unwrap();

        let mut history_txs_id = HashSet::<elements::Txid>::new();

        let scripts: Vec<elements::Script> = addrs
            .iter()
            .map(|x| x.script_pubkey().into_bytes())
            .map(|x| elements::Script::from(x))
            .collect();
        let b_scripts: Vec<bitcoin::Script> = addrs
            .iter()
            .map(|x| x.script_pubkey().into_bytes())
            .map(|x| bitcoin::Script::from(x))
            .collect();
        let result: Vec<Vec<GetHistoryRes>> = self
            .client
            .batch_script_get_history(b_scripts.iter())
            .unwrap();
        let flattened: Vec<GetHistoryRes> = result.into_iter().flatten().collect();
        Ok(self.download_txs_with_height(flattened, &scripts)?)
    }



    fn download_txs_with_height(
        &self,
        history_txs_id: Vec<GetHistoryRes>,
        scripts: &Vec<elements::Script>,
    ) -> Result<EDKTransactionDetails, bdk::Error> {
        let mut txs = vec![];
        let mut unblinds = vec![];
        // BETxid has to be converted into bitcoin::Txid for rust-electrum-client
        let txs_to_download: Vec<bitcoin::Txid> = history_txs_id
            .iter()
            .map(|x| x.tx_hash)
            .collect();
        let txs_height: Vec<i32> = history_txs_id
            .iter()
            .map(|x| x.height)
            .collect();
        if txs_to_download.is_empty() {
            Ok(EDKTransactionDetails::default())
        } else {
            let txs_bytes_downloaded = self
                .client
                .batch_transaction_get_raw(txs_to_download.iter())
                .unwrap();
            let mut txs_downloaded: Vec<elements::Transaction> = vec![];

            for vec in txs_bytes_downloaded {
                let tx: elements::Transaction = elm_des(&vec).unwrap();
                txs_downloaded.push(tx);
            }
            let txs_downloaded_with_height:Vec<TxWithHeight> = txs_downloaded.iter()
                                                            .zip(txs_height.iter())
                                                            .map(|(t,h)| TxWithHeight{tx: t.to_owned(), tx_height:h.to_owned()})
                                                            .collect();
            //let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded_with_height.into_iter() {
                let txid = tx.tx.txid();
                for (i, output) in tx.tx.output.iter().enumerate() {
                    let script = output.script_pubkey.clone();
                    if scripts.contains(&script) {
                        let vout = i as u32;
                        let outpoint = elements::OutPoint {
                            txid: tx.tx.txid(),
                            vout,
                        };
                        match self.try_unblind(outpoint, output.clone()) {
                            Ok(unblinded) => unblinds.push((outpoint, unblinded,tx.tx_height)),
                            Err(_) => println!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint),
                        }
                    }
                }
                txs.push((txid, tx.tx, tx.tx_height));
            }

            Ok(EDKTransactionDetails { txs, unblinds })
        }
    }

    pub fn balance_addresses(&self, addrs: Vec<Address>) -> Result<DownloadTxResult, bdk::Error> {
        //let client = Client::new("ssl://blockstream.info:995").unwrap();

        let mut history_txs_id = HashSet::<elements::Txid>::new();
        let mut heights_set = HashSet::new();
        let mut txid_height = HashMap::<elements::Txid, _>::new();

        let scripts: Vec<elements::Script> = addrs
            .iter()
            .map(|x| x.script_pubkey().into_bytes())
            .map(|x| elements::Script::from(x))
            .collect();
        let b_scripts: Vec<bitcoin::Script> = addrs
            .iter()
            .map(|x| x.script_pubkey().into_bytes())
            .map(|x| bitcoin::Script::from(x))
            .collect();
        let result: Vec<Vec<GetHistoryRes>> = self
            .client
            .batch_script_get_history(b_scripts.iter())
            .unwrap();
        let flattened: Vec<GetHistoryRes> = result.into_iter().flatten().collect();
        for el in flattened {
            // el.height = -1 means unconfirmed with unconfirmed parents
            // el.height =  0 means unconfirmed with confirmed parents
            // but we threat those tx the same
            let height = el.height.max(0);
            heights_set.insert(height as u32);
            let tx = elements::Txid::from_hash(el.tx_hash.as_hash());
            if height == 0 {
                txid_height.insert(tx, None);
            } else {
                txid_height.insert(tx, Some(height as u32));
            }
            history_txs_id.insert(tx);
        }
        Ok(self.download_txs(&history_txs_id, &scripts)?)
    }

    fn download_txs(
        &self,
        history_txs_id: &HashSet<elements::Txid>,
        scripts: &Vec<elements::Script>,
    ) -> Result<DownloadTxResult, bdk::Error> {
        let mut txs = vec![];
        let mut unblinds = vec![];
        // BETxid has to be converted into bitcoin::Txid for rust-electrum-client
        let txs_to_download: Vec<bitcoin::Txid> = history_txs_id
            .iter()
            .map(|x| bitcoin::Txid::from_hash(x.as_hash()))
            .collect();
        if txs_to_download.is_empty() {
            Ok(DownloadTxResult::default())
        } else {
            let txs_bytes_downloaded = self
                .client
                .batch_transaction_get_raw(txs_to_download.iter())
                .unwrap();
            let mut txs_downloaded: Vec<elements::Transaction> = vec![];
            for vec in txs_bytes_downloaded {
                let tx: elements::Transaction = elm_des(&vec).unwrap();
                txs_downloaded.push(tx);
            }
            //let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.into_iter() {
                let txid = tx.txid();
                for (i, output) in tx.output.iter().enumerate() {
                    let script = output.script_pubkey.clone();
                    if scripts.contains(&script) {
                        let vout = i as u32;
                        let outpoint = elements::OutPoint {
                            txid: tx.txid(),
                            vout,
                        };
                        match self.try_unblind(outpoint, output.clone()) {
                            Ok(unblinded) => unblinds.push((outpoint, unblinded)),
                            Err(_) => println!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint),
                        }
                    }
                }
                txs.push((txid, tx));
            }

            Ok(DownloadTxResult { txs, unblinds })
        }
    }

    pub fn try_unblind(
        &self,
        outpoint: elements::OutPoint,
        output: elements::TxOut,
    ) -> Result<TxOutSecrets, bdk::Error> {
        match (output.asset, output.value, output.nonce) {
            (
                Asset::Confidential(_),
                confidential::Value::Confidential(_),
                Nonce::Confidential(_),
            ) => {
                let script = output.script_pubkey.clone();
                let blinding_sk = self.master_blinding_key.derive_blinding_key(&script);
                //let blinding_pk = PublicKey::from_secret_key(&self.secp, &blinding_sk);
                let r_tx_out_secrets = output.unblind(&self.secp, blinding_sk);
                //println!("Unblinded outpoint:{} asset:{} value:{}", outpoint, tx_out_secrets.asset.to_string(), tx_out_secrets.value);
                //TODO add cutom Error enum and mapping between bdk and edk errors
                match r_tx_out_secrets {
                    Ok(tx_o_s) => {Ok(tx_o_s)}
                    Err(_) => {Err(bdk::Error::Generic("unbinging error".into()))}
                }
            }
            (Asset::Explicit(asset_id), confidential::Value::Explicit(satoshi), _) => {
                let asset_bf = AssetBlindingFactor::from_slice(&[0u8; 32]).unwrap();
                let value_bf = ValueBlindingFactor::from_slice(&[0u8; 32]).unwrap();
                let tx_out_secrets = TxOutSecrets {
                    asset: asset_id,
                    asset_bf: asset_bf,
                    value: satoshi,
                    value_bf: value_bf,
                };
                Ok(tx_out_secrets)
            }
            _ => Err(bdk::Error::Generic("Unexpected asset/value/nonce".into())),
        }
    }

}

fn main() {}

