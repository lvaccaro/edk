use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::str::FromStr;
use std::cell::RefCell;

pub extern crate bdk;
pub extern crate bip39;
pub extern crate elements_miniscript as miniscript;
pub extern crate serde;

use miniscript::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use miniscript::bitcoin::network::constants::Network;
use miniscript::elements::confidential::{
    self, Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
};
use miniscript::elements::encode::deserialize as elm_des;
use miniscript::elements::encode::serialize as elm_ser;
use miniscript::elements::secp256k1_zkp::{All, PublicKey, Secp256k1};
use miniscript::elements::slip77::MasterBlindingKey;
use miniscript::elements::TxOutSecrets;
use miniscript::elements::{Address, AddressParams};
use miniscript::{Descriptor, DescriptorPublicKey, DescriptorTrait, TranslatePk2};

use bdk::database::memory::MemoryDatabase;
use bdk::database::{BatchDatabase, BatchOperations, Database};
use bdk::electrum_client::{
    Client, ConfigBuilder, ElectrumApi, GetHistoryRes, ListUnspentRes, Socks5Config,
};
use serde::{Deserialize, Serialize};

pub enum ScriptType {
    P2shP2wpkh = 0,
    P2wpkh = 1,
    P2pkh = 2,
}

#[derive(Default)]
struct DownloadTxResult {
    txs: Vec<(elements::Txid, elements::Transaction)>,
    unblinds: Vec<(elements::OutPoint, elements::TxOutSecrets)>,
}

pub struct Wallet<D> {
    descriptor: Descriptor<DescriptorPublicKey>,
    master_blinding_key: MasterBlindingKey,
    secp: Secp256k1<All>,
    client: Client,
    database: RefCell<D>,
    network: &'static AddressParams
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
            network
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
            .derive(index)
            .translate_pk2(|xpk| xpk.derive_public_key(&self.secp))
            .unwrap();
        let unconfidential_address = xpk.address(&self.network).unwrap();
        let script_pubkey = xpk.script_pubkey();
        let blinding_sk = self.master_blinding_key.derive_blinding_key(&script_pubkey);
        let blinding_pk = PublicKey::from_secret_key(&self.secp, &blinding_sk);
        let confidential_address = unconfidential_address.to_confidential(blinding_pk);
        Ok(confidential_address)
    }

    // Return a newly derived address using the external descriptor
    fn get_new_address(&mut self) -> Result<Address, bdk::Error> {
        let index = match self.descriptor.is_deriveable() {
            false => 0,
            true => self
                .database
                .increment_last_index(bdk::KeychainKind::External)?,
        };
        let addr = self.get_address(index)?;
        Ok(addr)
    }

    fn get_previous_addresses(&mut self) -> Result<Vec<Address>, bdk::Error> {
        let mut addresses = vec![];
        for i in 0..self
            .database
            .get_last_index(bdk::KeychainKind::External)?
            .unwrap_or(0)
            + 1
        {
            addresses.push(self.get_address(i)?);
            //println!("{} {} {}",i, self.get_address(i)?, self.database.get_last_index(bdk::KeychainKind::External)?.unwrap_or(0));
        }
        Ok(addresses)
    }

    fn is_mine_address(&mut self, addr: &Address) -> Result<bool, bdk::Error> {
        Ok(self.get_previous_addresses()?.contains(addr))
    }

    fn balance(&mut self) -> Result<HashMap<String, u64>, bdk::Error> {
        let addrs: Vec<Address> = self.get_previous_addresses()?;
        let mut balances = HashMap::new();

        for unblind in self.balance_addresses(addrs)?.unblinds {
            let tx_out = unblind.1;
            *balances.entry(tx_out.asset.to_string()).or_insert(0) += tx_out.value;
        }
        Ok(balances)
    }

    fn balance_addresses(&mut self, addrs: Vec<Address>) -> Result<DownloadTxResult, bdk::Error> {
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
        &mut self,
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
            println!("txs_downloaded {}", txs_downloaded.len());
            //let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.into_iter() {
                let txid = tx.txid();
                println!("compute OutPoint Unblinded");
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
                let tx_out_secrets = output.unblind(&self.secp, blinding_sk).unwrap();
                //println!("Unblinded outpoint:{} asset:{} value:{}", outpoint, tx_out_secrets.asset.to_string(), tx_out_secrets.value);
                Ok(tx_out_secrets)
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

#[cfg(test)]
pub mod test {

    use super::*;

    fn aqua_subaccount_derivation(
        seed: &[u8],
        bip32_account_num: u32,
        script_type: &ScriptType,
        purpose: u32,
    ) -> Result<ExtendedPubKey, bdk::Error> {
        let secp = Secp256k1::new();
        let network = bitcoin::network::constants::Network::Bitcoin;
        let master_xprv = ExtendedPrivKey::new_master(network, &seed).unwrap();
        let master_xpub = ExtendedPubKey::from_private(&secp, &master_xprv);
        let master_blinding_key = MasterBlindingKey::new(&seed);

        // derive subaccount xprv & xpub
        let coin_type = 1776; // for liquid
        let path: bitcoin::util::bip32::DerivationPath =
            format!("m/{}'/{}'/{}'", purpose, coin_type, bip32_account_num)
                .parse()
                .unwrap();
        let xprv = master_xprv.derive_priv(&secp, &path).unwrap();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);

        // get internal chain for not change address
        let chain = xpub.ckd_pub(&secp, 0.into()).unwrap();
        Ok(chain)
    }

    fn aqua_address_derivation(
        chain: bitcoin::util::bip32::ExtendedPubKey,
        index: u32,
        script_type: &ScriptType,
        master_blinding_key: &MasterBlindingKey,
    ) -> Result<Address, bdk::Error> {
        let secp = Secp256k1::new();
        let child_key = chain.ckd_pub(&secp, index.into()).unwrap().public_key;
        let params: &'static AddressParams = &AddressParams::LIQUID;
        let address = match script_type {
            ScriptType::P2pkh => Address::p2pkh(&child_key, None, params),
            ScriptType::P2shP2wpkh => Address::p2shwpkh(&child_key, None, params),
            ScriptType::P2wpkh => Address::p2wpkh(&child_key, None, params),
        };
        let script_pubkey = address.script_pubkey();
        //println!("xpk {}", &script_pubkey.to_string());
        let blinding_sk = master_blinding_key.derive_blinding_key(&script_pubkey);
        let blinding_pk = PublicKey::from_secret_key(&secp, &blinding_sk);
        let confidential_address = address.to_confidential(blinding_pk);
        Ok(confidential_address)
    }

    fn aqua_address_derivation_descriptor(
        chain: bitcoin::util::bip32::ExtendedPubKey,
        index: u32,
        script_type: &ScriptType,
        master_blinding_key: &MasterBlindingKey,
    ) -> Result<Address, bdk::Error> {
        let secp = Secp256k1::new();
        let desc = format!("{}({}/*)", "elwpkh", &chain.to_string());

        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();
        let xpk = descriptor
            .derive(1)
            .translate_pk2(|xpk| xpk.derive_public_key(&secp))
            .unwrap();
        //println!("xpk {}", &xpk.script_pubkey().to_string());
        let unconfidential_address = xpk.address(&AddressParams::LIQUID).unwrap();
        let script_pubkey = xpk.script_pubkey();
        let blinding_sk = master_blinding_key.derive_blinding_key(&script_pubkey);
        let blinding_pk = PublicKey::from_secret_key(&secp, &blinding_sk);
        let confidential_address = unconfidential_address.to_confidential(blinding_pk);
        Ok(confidential_address)
    }

    #[test]
    fn test_aqua_derivation() {
        let mnemonic = "all all all all all all all all all all all all";
        let seed = bip39::Mnemonic::from_str(mnemonic)
            .unwrap()
            .to_seed_normalized("");
        let master_blinding_key = MasterBlindingKey::new(&seed);

        // 0="p2sh-p2wpkh" 1="p2wpkh" 2="p2pkh" , 49="p2sh-p2wpkh" 84="p2wpkh" 44="p2pkh"
        // let (bip32_account_num, script_type, purpose) = (0, ScriptType::P2shP2wpkh, 49);let chain = aqua_subaccount_derivation(&seed, bip32_account_num, &script_type, purpose).unwrap();

        let (bip32_account, script_type, purpose) = (1, ScriptType::P2wpkh, 84);
        let chain =
            aqua_subaccount_derivation(&seed, bip32_account, &script_type, purpose).unwrap();
        assert_eq!(
            "xpub6F33eZ1QWddkNKw27gdgACBGorYVU4iqJQwMDL85jVeiZKSjFbnKhJr15DtzBuiDLHAEr2aXk2aXahLq8Jpt9KZh1ubHuCc9Nbf65d65kPH",
            &chain.to_string()
        );

        let addr = aqua_address_derivation(chain, 1, &script_type, &master_blinding_key).unwrap();
        assert_eq!(
            "lq1qqwygr58ye8fs69lrweqpj20lal8nyqxpygpqw5er4p6gsazdcqpzd0yf4xcrlme85chya4tsmrwdrgrgt92gchw9fvzy5r5m3",
            &addr.to_string()
        );

        let addr = aqua_address_derivation_descriptor(chain, 1, &script_type, &master_blinding_key)
            .unwrap();
        assert_eq!(
            "lq1qqwygr58ye8fs69lrweqpj20lal8nyqxpygpqw5er4p6gsazdcqpzd0yf4xcrlme85chya4tsmrwdrgrgt92gchw9fvzy5r5m3",
            &addr.to_string()
        );

        let desc = format!("{}({}/*)", "elwpkh", &chain.to_string());
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();
        assert_eq!(
            "elwpkh(xpub6F33eZ1QWddkNKw27gdgACBGorYVU4iqJQwMDL85jVeiZKSjFbnKhJr15DtzBuiDLHAEr2aXk2aXahLq8Jpt9KZh1ubHuCc9Nbf65d65kPH/*)#yvsg4jzf",
            &descriptor.to_string()
        );

        let database = MemoryDatabase::new();

        let client = Client::new("ssl://blockstream.info:995").unwrap();
        let mut wallet = Wallet::new(descriptor, master_blinding_key,
            MemoryDatabase::new(),
            client,
            &AddressParams::LIQUID).unwrap();
        let addr = wallet.get_new_address().unwrap();
        let addr = wallet.get_new_address().unwrap();
        //let addr2 = wallet.get_new_address().unwrap();
        assert_eq!(
            "lq1qqwygr58ye8fs69lrweqpj20lal8nyqxpygpqw5er4p6gsazdcqpzd0yf4xcrlme85chya4tsmrwdrgrgt92gchw9fvzy5r5m3",
            &addr.to_string()
        );

        let mine = wallet.is_mine_address(&addr).unwrap();
        assert!(mine);

        /*let balance = wallet.balance().unwrap();
        println!("AssetId: Value");
        for b in balance {
            println!("{}: {}", b.0, b.1);
        }*/
    }
}
