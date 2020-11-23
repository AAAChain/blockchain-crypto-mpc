package main

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	pRIVATEKEY    = "2e86e0201f22cf99ad9e6f7ffcac97691756182849c9cf9c2fc985ec6b655e6b"
	wALLETADDRESS = "0xcF7939751bD76E84dD5C258F01F209eDdC579Dcc"
)

func main() {
	privateKey, err := crypto.HexToECDSA(pRIVATEKEY)
	if err != nil {
		log.Fatal(err)
	}

	rawBytes, err := ioutil.ReadFile("pubkey.dat")
	if err != nil {
		panic(err)
	}

	// var pubKey ecdsa.PublicKey
	// a, b := asn1.Unmarshal(rawBytes, &pubKey)
	// fmt.Printf("pubKey:%+v a:%+v b:%+v\n", pubKey, a, b)

	log.Println("fromMPC", rawBytes)
	log.Println("fromMPC", string(rawBytes))
	log.Println("fromMPC", hex.EncodeToString(rawBytes))
	log.Println("fromGOM", elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y))
	rawBytes = rawBytes[23:]
	log.Println("MPC-after", rawBytes)

	pubKey, err := crypto.UnmarshalPubkey(rawBytes)
	if err != nil {
		panic(err)
	}

	address := publicKeyBytesToAddress(rawBytes).String()
	if address != wALLETADDRESS {
		log.Println(address, "wallet address missmatch")
		os.Exit(0)
	}

	client, err := ethclient.Dial("https://kovan.infura.io/v3/954d5bbb46b047d28f31c369502a3da6")
	if err != nil {
		log.Fatal(err)
	}

	fromAddress := common.HexToAddress(wALLETADDRESS)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(100000000000000000) // in wei (0.001 eth)
	gasLimit := uint64(21000)               // in units
	gasPrice := big.NewInt(20000000000)

	toAddress := common.HexToAddress("0x3bCc7ca67F368fFc0556b2AE83e28dA2Ed4b841b")
	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signer := types.NewEIP155Signer(chainID)
	h := signer.Hash(tx)
	ioutil.WriteFile("tx.raw", h[:], os.ModePerm)

	// h1, _ := ioutil.ReadFile("tx.raw")

	// sigGo, err := crypto.Sign(h1[:], privateKey)
	// if err != nil {
	// 	panic(err)
	// }

	sigRaw, err := ioutil.ReadFile("sign.raw")
	if err != nil {
		panic(err)
	}

	signature, err := btcec.ParseDERSignature(sigRaw, btcec.S256())
	if err != nil {
		panic(err)
	}

	curve := btcec.S256()
	for i := 0; i < (curve.H+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, signature, h[:], i, true)
		if err == nil && pk.X.Cmp(pubKey.X) == 0 && pk.Y.Cmp(pubKey.Y) == 0 {
			fmt.Printf("\n\n\n================\nbingo %+v\n================\n\n\n", curve.BitSize)
			result := make([]byte, 1, 2*curve.BitSize+1)
			result[0] = 27 + byte(i)
			// Not sure this needs rounding but safer to do so.
			curvelen := (curve.BitSize + 7) / 8

			// Pad R and S to curvelen if needed.
			bytelen := (signature.R.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, signature.R.Bytes()...)

			bytelen = (signature.S.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, signature.S.Bytes()...)
			sigRaw = result
		}
	}

	// if !reflect.DeepEqual(sig, sigGo) {
	fmt.Printf("sig %+v\n", signature)
	fmt.Printf("sigSerialize %+v\n", signature.Serialize())
	fmt.Printf("sigRaw %+v\n", sigRaw)
	// 	return
	// }

	vv := sigRaw[0] - 27
	copy(sigRaw, sigRaw[1:])
	sigRaw[64] = vv

	r, s, v, err := signer.SignatureValues(tx, sigRaw)
	fmt.Printf("sigPy r:%+v s:%+v v:%+v err:%+v\n", r, s, v, err)

	// r, s, v, err = signer.SignatureValues(tx, sigGo)
	// fmt.Printf("sigGo r:%+v s:%+v v:%+v err:%+v\n", r, s, v, err)

	signedTx, err := tx.WithSignature(signer, sigRaw)
	if err != nil {
		panic(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())
}

func recoverKeyFromSignature(curve *btcec.KoblitzCurve, sig *btcec.Signature, msg []byte,
	iter int, doChecks bool) (*btcec.PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &btcec.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

func decompressPoint(curve *btcec.KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func publicKeyBytesToAddress(publicKey []byte) common.Address {
	buf := crypto.Keccak256(publicKey[1:])
	address := buf[12:]
	return common.HexToAddress(hex.EncodeToString(address))
}
