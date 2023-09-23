use bdk::{ Wallet};
// use bdk::SyncOptions;
use bdk::database::MemoryDatabase;
use bdk::wallet::AddressIndex::New;
use bdk::bitcoin::Network::{Testnet , Regtest};
use bdk::keys::bip39::{Language, Mnemonic,WordCount};
use bdk::keys::{ DescriptorKey,GeneratableKey, GeneratedKey,ExtendedKey,DerivableKey};
use bdk::Error as BDK_ERROR;
use bdk::bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;
use bdk::miniscript::{ miniscript,Segwitv0};
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::keys::DescriptorKey::Secret;
// use bdk::blockchain::ElectrumBlockchain;
// use bdk::electrum_client::Client;

fn main() -> Result<(), bdk::Error> {
  // let client = Client::new("ssl://electrum.blockstream.info:60002")?;
    // Generate a new mnemonic

    let secp = Secp256k1::new();
 let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| BDK_ERROR::Generic("Mnemonic generation error".to_string()))?;
    let mnemonic = mnemonic.into_key();

let xkey: ExtendedKey = (mnemonic.clone(), None).into_extended_key()?;
 //If the xpriv get compromised all the chid private keys can be derived through the
 //extended_private_key   
let xprv = xkey.into_xprv(Regtest).ok_or_else(|| {
        BDK_ERROR::Generic("Privatekey info not found!".to_string())
    })?;
    let fingerprint = xprv.fingerprint(&secp);


 let path = DerivationPath::from_str("m/84h/1h/0h").unwrap();

    println!("path: {}", path);
    let derived_xprv = &xprv.derive_priv(&secp, &path)?;

    let origin: KeySource = (fingerprint, path);

let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
        derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;



let mut xpub: String = "".to_string();
let mut xpriv : String = "".to_string();
if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
        let desc_pubkey = desc_seckey
            .to_public(&secp).map_err(|e| BDK_ERROR::Generic(e.to_string()))?;
         xpub = desc_pubkey.to_string();
        let  xpriv_str = &desc_seckey.to_string();
        xpriv = xpriv_str.to_string();
        println!("xpub :  {}", &xpub);
        println!("xprv :  {}", &xpriv);
    } else {
    BDK_ERROR::Generic("Error deriving xpub / xpriv ".to_string());  
    }

    println!(" mnemonic: {}", &mnemonic);
    println!("fingerprint: {}", &fingerprint);
    println!("derived_xprv: {}",&derived_xprv);
    println!("formating.. to withness privatekey hash +++ : {}", format!("wpkh({})", &xpub),
 );
// Create a new  BitCoin Wallet
    // let wallet = Wallet::new(
    //     "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
    //     Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
    //     Testnet,
    //     MemoryDatabase::default(),
    // )?;
    //
 //

fn desc_and_change_desc(_x: &str) -> (String, String) {
    let original = format!("wpkh({})", _x);
    let reformatted = original.replace("'", "h");
    let des = reformatted.replace("*", "0/*");
    println!("Formatting.. child keys starting from the index 0: {}", &des);

    let c_des = reformatted.replace("*", "1/*");
    (des, c_des)
}

let (descriptor,change_descriptor) = desc_and_change_desc(&xpub);

let wallet = Wallet::new(
    &descriptor,   // recieving addresses
     Some(&change_descriptor),           // change addresses  
    Testnet,
    MemoryDatabase::default(),
)?;

// let blockchain = ElectrumBlockchain::from(client);

    // wallet.sync(&blockchain, SyncOptions::default())?;

    println!("Addresses derived with tpub");
    //READ ONLY child addresses created  with xpub can be used to create unsinged tx but can't be used
    //to send acctual BTC on chain   
    println!("Address #0: {}", wallet.get_address(New)?);
    println!("Address #1: {}", wallet.get_address(New)?);
    println!("Address #2: {}", wallet.get_address(New)?);

 let (desc_prv, c_des_prv) =desc_and_change_desc(&xpriv);

let signer = Wallet::new(
    &desc_prv,
    Some(&c_des_prv),
    Testnet,
    MemoryDatabase::default(), 
    )?;

    println!("Addresses derived with tpriv");
    // child addresses created  with xpiv can be used to create singed tx but can be used
    //to send  BTC on chain   
    println!("Address #0: {}", signer.get_address(New)?);
    println!("Address #1: {}", signer.get_address(New)?);
    println!("Address #2: {}", signer.get_address(New)?);

    Ok(())
    }
