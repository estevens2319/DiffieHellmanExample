"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  //printCryptoKey, // async
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
} from "./lib.js";
import { govEncryptionDataStr } from "./lib.js";
const { subtle } = require("crypto").webcrypto;

/********* Implementation ********/

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {};                            // data for each active connection
    this.certs = {};                            // certificates of other users
    this.EGKeyPair = {};                        // keypair from generateCertificate
    this.stringifyCert = function (cert) {      //function to make a certificate a string
      if (typeof cert == "object") {
        return JSON.stringify(cert);
      } else if (typeof cert == "string") {
        return cert;
      } else {
        throw "Certificate is not a JSON or string";
      }
    };

  }

  /**
     * Generate a certificate to be stored with the certificate authority.
     * The certificate must contain the field "username".
     *
     * Arguments:
     *   username: string
     *
     * Return Type: certificate object/dictionary
     */
  async generateCertificate(username) {
    console.log("Generating Certificate");
    var keypairObject = await generateEG();                                    // assign EG keypairs to variable keypairObject
    this.EGKeyPair = keypairObject;                                            // store the new DH keys as our EGKeyPair
    const certificate = { "username": username, "pubkey": keypairObject.pub }; // Creates new certificate with 'username' and 'pubkey' as dict values
    return certificate;                                                        // returns the certificate created for later use
  }



  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */

  async receiveCertificate(certificate, signature) {
    console.log("Recieving Certificate");

    if (await verifyWithECDSA(this.caPublicKey, await this.stringifyCert(certificate), signature)) {  //Verifies that the signature is correct, if not, return Error

      this.certs[certificate.username] = certificate;   // adds the certificate to stored certificates

      let newStateVars = {
        "DHs": "",        // DH Ratchet key pair (the "sending" or "self" ratchet key)
        "DHr": "",        // DH Ratchet public key (the "received" or "remote" key)
        "RK": "",         // 32 byte root key
        "CKs": "",        // 32 byte sending chain key
        "CKr": "",        // 32 byte receiving chain key
        "Ns": 0,          // number of sending messages
        "Nr": 0,          // number of receiving messages
        "Pn": 0,          // number of messages in previous sending chain
        "MKSKIPPED": {},  // dictionary of skipped message numbers 
      }
      this.conns[certificate.username] = newStateVars; // Adds the new state variables to the connection with the certificates username 
    }
    else {
      throw ("Error: Signature verification failed."); //error if signature is incorrect
    }
  }


  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */

  // Helper function to the send message function for initializing a new conversation from the sender side
  async initializeAlice(state, SK, bob_dh_public_key) {
    console.log("Initialization of Alice");
    state.DHs = await generateEG();                       // assign new EG keypairs to state.DHs
    state.DHr = bob_dh_public_key;                        // bob's public key is stored as the DHr
    let DH = await computeDH(state.DHs.sec, state.DHr);   // computeDH using Alice secret key and Bobs pub key to be used in HKDF
    let RKCK = await HKDF(SK, DH, "ratchet-str");         // Run HKDF on SK and DH and assign outputs to RkCk
    state.RK = RKCK[0];                                   // assign HKDF encyrption key to be the Root key
    state.CKs = RKCK[1];                                  // assign HKDF authentication key to the sending Chain key
    state.CKr = 0;
    state.Ns = 0;
    state.Nr = 0;                                         // initialize everything else to 0
    state.PN = 0;
    state.MKSKIPPED = {};
  }

  //sendMessage function definition
  async sendMessage(name, plaintext) {
    let state = this.conns[name];                 // get all the connection variables 
    let recCert = this.certs[name];               // get the recipients certificate
    console.log("Sending message to: " + name);
    let header, cipher = "";


    // check if this is the first message and if so do initialization
    if (state.Ns === 0 && state.Nr === 0) {
      let SK = await computeDH(this.EGKeyPair.sec, recCert.pubkey);   // For the first message get the root key (aka secret key) using sender and recievers DH keys from their certificates  
      await this.initializeAlice(state, SK, recCert.pubkey);          // initialize the sender's variables
      let CKs = state.CKs                                             // temporarily store current CKs  
      state.CKs = await HMACtoHMACKey(CKs, "1");                      // generate the new sending key 
      let messageKey = await HMACtoHMACKey(CKs, "2");                 // generate the message key    
      state.Ns = state.Ns + 1;                                        // add 1 to the number of sent messages 
      let IV = await genRandomSalt();                                 // generate a random IV from genRandomSalt
      let keySwitch = await HMACtoAESKey(messageKey, "switch");       //convert the HMAC message key to an AES key

      // Government Stuff Starts
      let ivGov = await genRandomSalt();                                // generate random IV for government encryption
      let vGov = await computeDH(state.DHs.sec, this.govPublicKey);     // use the senders secret key and the governments public key to create a new key
      let govSwitch = await HMACtoAESKey(vGov, govEncryptionDataStr);   // convert the HMAC vGov key to an AES key to encrypt with
      let stringKey = await subtle.exportKey("raw", keySwitch);         // convert the message key (already converted to AES) to a string to be used as the data to be encrypted 
      let cGov = await encryptWithGCM(govSwitch, stringKey, ivGov);     // Encrypt the message key string using the key created with the government's key
      // Government Stuff Ends

      // create the header containing everything the reciever needs and everything the government needs, and nothing the adversary can use. 
      header = {
        "DHs": state.DHs.pub,     // senders new El Gamal public key
        "PN": state.PN,           // updated number of messages in the message chain 
        "Ns": state.Ns,           // updated number of messages sent
        "receiver_iv": IV,        // random IV used for decrypting
        "ivGov": ivGov,           // governments random IV used for decrypting 
        "vGov": state.DHs.pub,    // The key created by computing DH on the senders secret key and the governments public key
        "cGov": cGov,             // the cipher text for the government to decrypt containing the message key
      };
      let stringedHeader = await this.stringifyCert(header);                    // convert the header to a string to be passed as an argument to the encryption
      cipher = await encryptWithGCM(keySwitch, plaintext, IV, stringedHeader);  // encrypt the plaintext using the switched message key, the random IV, and the header string 
      return [header, cipher];                                                  //return header and ciphertext for the receiver or government to decrypt 
    }
    else {
      state.DHs = await generateEG();                           // generate fresh DH key pair
      let DH = await computeDH(state.DHs.sec, state.DHr);       // Compute DH using the recievers key and the senders secret key
      let RKCK = await HKDF(state.RK, DH, "ratchet-str");       // Run HKDF on the Root Key and DH and assign outputs to RkCk
      state.RK = RKCK[0];                                       // assign HKDF encyrption key to be the Root key
      state.CKs = RKCK[1];                                      // assign HKDF authentication key to the sending Chain key
      let CKs = state.CKs                                       // temporarily store current CKs  
      state.CKs = await HMACtoHMACKey(CKs, "1");                // generate the new sending key 
      let messageKey = await HMACtoHMACKey(CKs, "2");           // generate the message Key    
      state.Ns = state.Ns + 1;                                  // add 1 to the number of sent messages 
      let IV = await genRandomSalt();                           // generate a random IV from genRandomSalt
      let keySwitch = await HMACtoAESKey(messageKey, "switch"); //convert the HMAC message key to an AES key

      // Government Stuff Starts
      let ivGov = await genRandomSalt();                                // generate random IV for government encryption
      let vGov = await computeDH(state.DHs.sec, this.govPublicKey);     // use the senders secret key and the governments public key to create a new key
      let govSwitch = await HMACtoAESKey(vGov, govEncryptionDataStr);   // convert the HMAC vGov key to an AES key to encrypt with
      let stringKey = await subtle.exportKey("raw", keySwitch);         // convert the message key (already converted to AES) to a string to be used as the data to be encrypted 
      let cGov = await encryptWithGCM(govSwitch, stringKey, ivGov);     // Encrypt the message key string using the key created with the government's key
      // Government Stuff Ends

      header = {
        "DHs": state.DHs.pub,     // senders new El Gamal public key
        "PN": state.PN,           // updated number of messages in the message chain 
        "Ns": state.Ns,           // updated number of messages sent
        "receiver_iv": IV,        // random IV used for decrypting
        "ivGov": ivGov,           // governments random IV used for decrypting 
        "vGov": state.DHs.pub,    // The key created by computing DH on the senders secret key and the governments public key
        "cGov": cGov,             // the cipher text for the government to decrypt containing the message key
      };
      let stringedHeader = await this.stringifyCert(header);                    // convert the header to a string to be passed as an argument to the encryption
      cipher = await encryptWithGCM(keySwitch, plaintext, IV, stringedHeader);  // encrypt the plaintext using the switched message key, the random IV, and the header string 
      return [header, cipher];                                                  //return header and ciphertext for the receiver or government to decrypt 
    }

  }


  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */

  // Helper function to the receive message function for initializing a new conversation from the receiver side
  async initializeBob(state, SK, bob_dh_key_pair) {
    console.log("Initializing Bob");
    state.DHs = bob_dh_key_pair;     // assign bob dh key pair to state.DHs
    state.DHr = "";
    state.RK = SK;                   // assign bob SK to state.RK
    state.CKs = "";
    state.CKr = "";                  // initialize everything else to 0
    state.Ns = 0;
    state.Nr = 1;                    // since this is initialize runs when a message is received, the number of received messages starts at 1 
    state.PN = 0;
    state.MKSKIPPED = {};
  }

  //recieveMessage function
  async receiveMessage(name, [header, ciphertext]) {
    let state = this.conns[name];                 // get all the connection variables
    let sentCert = this.certs[name];              // get the senders certificate
    let plaintext = "";

    // check if the message coming in is out of order
    if (header.Ns !== (state.Nr + 1)) {

      // check if this is the first message and if so initialize
      if (state.Nr === 0 && state.Ns === 0) {
        let SK = await computeDH(this.EGKeyPair.sec, sentCert.pubkey);  // compute initial SK 
        await this.initializeBob(state, SK, this.EGKeyPair);            // perform initialization set up
      }
      // store the data needed to compute the message key for when the message comes in later 
      state.MKSKIPPED[state.Nr] = {
        "RK": state.RK,
        "DH1": state.DHs.sec,
      }
      RKCK = await HKDF(state.RK, state.DHr, "ratchet-str");  
      throw ("Error Out of order");  // Did not end up completing this functionality
    }

    else {
      // check if this is the first sent or received message
      if (state.Nr === 0 && state.Ns === 0) {
        let SK = await computeDH(this.EGKeyPair.sec, sentCert.pubkey);                // Compute the initial Root key (aka sk)
        await this.initializeBob(state, SK, this.EGKeyPair);                          // Perform initialization for the receiver
        state.DHr = header.DHs;                                                       // Store the messages DHs in our state's DHr
        let DH = await computeDH(state.DHs.sec, header.DHs);                          // Compute the DH for our states secret key and the messages public key
        let RKCK = await HKDF(SK, DH, "ratchet-str");                                 // compute HKDF on the Root Key (sk for first message) and the DH computation 
        state.RK = RKCK[0];                                                           // store the outcome of the HKDF as our current root key
        let messageKey = await HMACtoHMACKey(RKCK[1], "2");                           // generate the message key from the HKDF output
        let stringedHeader = await this.stringifyCert(header);                        // convert the received header into a string to be passed to decrypction
        let keySwitch = await HMACtoAESKey(messageKey, "switch");                     // convert the HMAC message key to an AES key for decryption 
        let IV = header.receiver_iv;                                                  // get the IV that was used for encryption
        plaintext = await decryptWithGCM(keySwitch, ciphertext, IV, stringedHeader);  // decrypt the cipher text 
        plaintext = byteArrayToString(plaintext);                                     // convert the byte array to a string
        return plaintext;                                                             // return the plaintext
      }

      else {
        state.Nr = state.Nr + 1;                                                      // increment the number of received messages  
        state.DHr = header.DHs;                                                       // Store the messages DHs in our state's DHr
        let DH = await computeDH(state.DHs.sec, header.DHs);                          // Compute the DH for our states secret key and the messages public key
        let RKCK = await HKDF(state.RK, DH, "ratchet-str");                           // compute HKDF on the Root Key and the DH computation 
        state.RK = RKCK[0];                                                           // store the outcome of the HKDF as our current root key
        let messageKey = await HMACtoHMACKey(RKCK[1], "2");                           // generate the message key from the HKDF output
        let stringedHeader = await this.stringifyCert(header);                        // convert the received header into a string to be passed to decrypction
        let keySwitch = await HMACtoAESKey(messageKey, "switch");                     // convert the HMAC message key to an AES key for decryption 
        let IV = header.receiver_iv;                                                  // get the IV that was used for encryption
        plaintext = await decryptWithGCM(keySwitch, ciphertext, IV, stringedHeader);  // decrypt the cipher text 
        plaintext = byteArrayToString(plaintext);                                     // convert the byte array to a string
        return plaintext;                                                             // return the plaintext
      }

    }
  }
};





