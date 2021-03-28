using System;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Nethereum.Util;
using Nethereum.Hex.HexConvertors.Extensions;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace ConsoleApp3
{
    class Program
    {
        static void Main(string[] args)
        {
            UserKeys keys = new UserKeys();
            Console.WriteLine("Public Key: " + keys.PublicKey);
            Console.WriteLine("Private Key: " + keys.PrivateKey + "\n\n");

            BlockChain chain = new BlockChain();
            Console.WriteLine("BlockChain Created. \n\n");

            Promise promise = new Promise("Any To Address", keys.PublicKey, "I promise to learn how blockchain works");
            Console.WriteLine("Promise Created.");

            EthECKey userPrivateKey = UserKeys.GetEthECKeyFromPrivateKey(keys.PrivateKey);
            promise.SignPromise(userPrivateKey);
            Console.WriteLine("Promise Signed.\n\n");


            Block block = new Block(DateTime.Now.ToString(), promise, chain.GetLatestBlock().Hash);
            Console.WriteLine("Block created.\n\n");
            chain.AddBlock(block);
            Console.WriteLine("Block added to chain.\n\n");

            Console.WriteLine("Is the chain valid?: " + chain.IsChainValid());
        }
    }


    public class UserKeys
    {
        public string PublicKey;
        public string PrivateKey;

        public UserKeys()
        {
            var privKey = EthECKey.GenerateKey(); // Random private key
            PublicKey = privKey.GetPubKeyNoPrefix().ToHex();
            PrivateKey = privKey.GetPrivateKey().Substring(2);
        }

        public static string GetPublicKeyString(EthECKey privateKey)
        {
            return privateKey.GetPubKeyNoPrefix().ToHex();
        }

        static public EthECKey GetEthECKeyFromPrivateKey(string privateKey)
        {
            return new EthECKey("0x"+privateKey);
        }
    }

    public class Promise
    {
        string ToAddress;
        string FromAddress;
        public string PromiseWording;
        EthECDSASignature Signature;

        public Promise(string toAddress, string fromAddress, string promiseWording)
        {
            ToAddress = toAddress;
            FromAddress = fromAddress;
            PromiseWording = promiseWording;
        }

        internal string CalculateHash()
        {
            SHA256 mySHA256 = SHA256.Create();
            byte[] bytes = Encoding.ASCII.GetBytes(ToAddress + FromAddress + PromiseWording);
            return mySHA256.ComputeHash(bytes).ToString();
        }

        public void SignPromise(EthECKey signingKey)
        {
            if (UserKeys.GetPublicKeyString(signingKey) != FromAddress)
            {
                throw new Exception("You cannot sign someone else's transaction.");
            }
            string promiseHash = CalculateHash();
            byte[] msgBytes = Encoding.UTF8.GetBytes(promiseHash);
            byte[] msgHash = new Sha3Keccack().CalculateHash(msgBytes);
            Signature = signingKey.SignAndCalculateV(msgHash);
        }

        public bool IsValid()
        {
            if (FromAddress == null) return true;
            if (Signature == null)
            {
                throw new Exception("No singature in this promise.");
            }
            byte[] hashBytes = Encoding.UTF8.GetBytes(CalculateHash());
            EthECKey pubKeyRecovered = EthECKey.RecoverFromSignature(Signature, hashBytes);
            return pubKeyRecovered.Verify(hashBytes, Signature);
        }

        public string ToJObjectString()
        {
            JObject promiseObject = new JObject(
                new JProperty(nameof(ToAddress), ToAddress),
                new JProperty(nameof(FromAddress), FromAddress),
                new JProperty(nameof(PromiseWording), PromiseWording),
                new JProperty(nameof(Signature), Signature.ToDER().ToHex()));
            return promiseObject.ToString();
        }
    }

    public class Block
    {
        string TimeStamp;
        public Promise Promise;
        public string PreviousHash;
        public string Hash;
        int Nonce;

        public Block(string timeStamp, Promise promise, string previousHash = "")
        {
            TimeStamp = timeStamp;
            Promise = promise;
            PreviousHash = previousHash;
            Hash = CalculateHash();
            Nonce = 0;
        }

        public string CalculateHash()
        {
            SHA256 mySHA256 = SHA256.Create();
            byte[] bytes;
            if (Promise != null)
            {
                bytes = Encoding.ASCII.GetBytes(TimeStamp + Promise.ToJObjectString() + Nonce);
            }
            else // Genesis block
            {
                bytes = Encoding.ASCII.GetBytes(TimeStamp + JsonSerializer.Serialize(Promise) + Nonce);
            }
            string hash = mySHA256.ComputeHash(bytes).ToHex();
            return hash;
        }

        public void MineBlock(int difficulty)
        {
            string difficultyPrefix = "";
            for (int i = 0; i < difficulty; i++)
            {
                difficultyPrefix += "0";
            }
            while (Hash.Substring(0, difficulty) != difficultyPrefix)
            {
                Nonce++;
                Hash = CalculateHash();
            }
            Console.WriteLine("Block mined: " + Hash);
        }

        public bool hasValidPromise()
        {
            return Promise.IsValid();
        }
    }

    public class BlockChain
    {
        public List<Block> Chain;
        const int Difficulty = 4;

        public BlockChain()
        {
            Chain = new List<Block>();
            Chain.Add(CreateGenesisBlock());
        }

        Block CreateGenesisBlock()
        {
            return new Block(DateTime.Now.ToString(), null, "0");
        }

        public Block GetLatestBlock()
        {
            return Chain.Last();
        }

        public void AddBlock(Block block)
        {
            block.MineBlock(Difficulty);
            Chain.Add(block);
        }

        public bool IsChainValid()
        {
            for (int i = 1; i < Chain.Count; i++)
            {
                Block currentBlock = Chain[i];
                Block previousBlock = Chain[i - 1];
                if (currentBlock.CalculateHash() != currentBlock.Hash)
                {
                    return false;
                }
                if (currentBlock.PreviousHash != previousBlock.Hash)
                {
                    return false;
                }
                if (!currentBlock.hasValidPromise())
                {
                    return false;
                }
            }
            return true;
        }
    }



}
