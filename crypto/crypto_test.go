// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"fmt"
)

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

// These tests are sanity checks.
// They should ensure that we don't e.g. use Sha3-224 instead of Sha3-256
// and that the sha3 library uses keccak-f permutation.
func TestKeccak256Hash(t *testing.T) {
	msg := []byte("abc")
	exp, _ := hex.DecodeString("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
	checkhash(t, "Sha3-256-array", func(in []byte) []byte { h := Keccak256Hash(in); return h[:] }, msg, exp)
}

func TestToECDSAErrors(t *testing.T) {
	if _, err := HexToECDSA("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
	if _, err := HexToECDSA("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
}

func BenchmarkSha3(b *testing.B) {
	a := []byte("hello world")
	for i := 0; i < b.N; i++ {
		Keccak256(a)
	}
}

func TestSign(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)

	msg := Keccak256([]byte("foo"))
	sig, err := Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	recoveredPub, err := Ecrecover(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	pubKey := ToECDSAPub(recoveredPub)
	recoveredAddr := PubkeyToAddress(*pubKey)
	if addr != recoveredAddr {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr)
	}

	// should be equal to SigToPub
	recoveredPub2, err := SigToPub(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	recoveredAddr2 := PubkeyToAddress(*recoveredPub2)
	if addr != recoveredAddr2 {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr2)
	}
}

func TestInvalidSign(t *testing.T) {
	if _, err := Sign(make([]byte, 1), nil); err == nil {
		t.Errorf("expected sign with hash 1 byte to error")
	}
	if _, err := Sign(make([]byte, 33), nil); err == nil {
		t.Errorf("expected sign with hash 33 byte to error")
	}
}

func TestNewContractAddress(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)
	genAddr := PubkeyToAddress(key.PublicKey)
	// sanity check before using addr to create contract address
	checkAddr(t, genAddr, addr)

	caddr0 := CreateAddress(addr, 0)
	caddr1 := CreateAddress(addr, 1)
	caddr2 := CreateAddress(addr, 2)
	checkAddr(t, common.HexToAddress("333c3310824b7c685133f2bedb2ca4b8b4df633d"), caddr0)
	checkAddr(t, common.HexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"), caddr1)
	checkAddr(t, common.HexToAddress("c9ddedf451bc62ce88bf9292afb13df35b670699"), caddr2)
}

func TestLoadECDSAFile(t *testing.T) {
	keyBytes := common.FromHex(testPrivHex)
	fileName0 := "test_key0"
	fileName1 := "test_key1"
	checkKey := func(k *ecdsa.PrivateKey) {
		checkAddr(t, PubkeyToAddress(k.PublicKey), common.HexToAddress(testAddrHex))
		loadedKeyBytes := FromECDSA(k)
		if !bytes.Equal(loadedKeyBytes, keyBytes) {
			t.Fatalf("private key mismatch: want: %x have: %x", keyBytes, loadedKeyBytes)
		}
	}

	ioutil.WriteFile(fileName0, []byte(testPrivHex), 0600)
	defer os.Remove(fileName0)

	key0, err := LoadECDSA(fileName0)
	if err != nil {
		t.Fatal(err)
	}
	checkKey(key0)

	// again, this time with SaveECDSA instead of manual save:
	err = SaveECDSA(fileName1, key0)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fileName1)

	key1, err := LoadECDSA(fileName1)
	if err != nil {
		t.Fatal(err)
	}
	checkKey(key1)
}

func TestValidateSignatureValues(t *testing.T) {
	check := func(expected bool, v byte, r, s *big.Int) {
		if ValidateSignatureValues(v, r, s, false) != expected {
			t.Errorf("mismatch for v: %d r: %d s: %d want: %v", v, r, s, expected)
		}
	}
	minusOne := big.NewInt(-1)
	one := common.Big1
	zero := common.Big0
	secp256k1nMinus1 := new(big.Int).Sub(secp256k1_N, common.Big1)

	// correct v,r,s
	check(true, 0, one, one)
	check(true, 1, one, one)
	// incorrect v, correct r,s,
	check(false, 2, one, one)
	check(false, 3, one, one)

	// incorrect v, combinations of incorrect/correct r,s at lower limit
	check(false, 2, zero, zero)
	check(false, 2, zero, one)
	check(false, 2, one, zero)
	check(false, 2, one, one)

	// correct v for any combination of incorrect r,s
	check(false, 0, zero, zero)
	check(false, 0, zero, one)
	check(false, 0, one, zero)

	check(false, 1, zero, zero)
	check(false, 1, zero, one)
	check(false, 1, one, zero)

	// correct sig with max r,s
	check(true, 0, secp256k1nMinus1, secp256k1nMinus1)
	// correct v, combinations of incorrect r,s at upper limit
	check(false, 0, secp256k1_N, secp256k1nMinus1)
	check(false, 0, secp256k1nMinus1, secp256k1_N)
	check(false, 0, secp256k1_N, secp256k1_N)

	// current callers ensures r,s cannot be negative, but let's test for that too
	// as crypto package could be used stand-alone
	check(false, 0, minusOne, one)
	check(false, 0, one, minusOne)
}

func checkhash(t *testing.T, name string, f func([]byte) []byte, msg, exp []byte) {
	sum := f(msg)
	if !bytes.Equal(exp, sum) {
		t.Fatalf("hash %s mismatch: want: %x have: %x", name, exp, sum)
	}
}

func checkAddr(t *testing.T, addr0, addr1 common.Address) {
	if addr0 != addr1 {
		t.Fatalf("address mismatch: want: %x have: %x", addr0, addr1)
	}
}

// test to help Python team with integration of libsecp256k1
// skip but keep it after they are done
func TestPythonIntegration(t *testing.T) {
	kh := "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	k0, _ := HexToECDSA(kh)

	msg0 := Keccak256([]byte("foo"))
	sig0, _ := Sign(msg0, k0)

	msg1 := common.FromHex("00000000000000000000000000000000")
	sig1, _ := Sign(msg0, k0)

	t.Logf("msg: %x, privkey: %s sig: %x\n", msg0, kh, sig0)
	t.Logf("msg: %x, privkey: %s sig: %x\n", msg1, kh, sig1)
}






///////////////////////////greg add 2018/07/04/////////////////////////////
/////////////////////////////////////////////////////////////////////////
func TestRingSign(t *testing.T){

	//1.环签名
	//func GenRingSignData(hashMsg string, privateKey string, publickeyset string) (string, error) {
	address := "0xb24f93396c915E003bd713319366c6fFA281cb9D"
	msg1,_:=hexutil.Decode(address)
	msg := Keccak256(msg1)
	msg2:=hexutil.Encode(msg)
	fmt.Println("msg--->",msg2)

	privateKey:= "0x6dc1c88c2362cb85d6468ba225c5c0b39bbb216c9b67ad65e54c0000b00257c5"

	//publickeyset1:="0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc"
	//publickeyset2:="0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455"
	//publickeyset3:="0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f"
	//
	//publickeyset:=[]string{publickeyset1,publickeyset2,publickeyset3}
	//publickeys:=strings.Join(publickeyset, ",")
	//


	publickeys:="0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc," +
		"0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455," +
		"0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4," +
		"0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f," +
		"0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4"
	res,keyimage,err:=GenRingSignData(msg2,privateKey,publickeys)
	if err!=nil{
		fmt.Println("ringsing error",err)
	}
	fmt.Println(res)
	fmt.Println(keyimage)

	//2.验证环签名
	//err,publickeys2,keyimage2,c,r:=DecodeRingSignOut(res)
	//fmt.Println("publickeys2",publickeys2)
	//fmt.Println("keyimage2",keyimage2)
	//fmt.Println("c",c)
	//fmt.Println("r",r)
	//verifyRES1:=verifyRingSign(msg,publickeys2,keyimage2,c,r)
	//fmt.Println(verifyRES1)

	verifyRES:=VerifyRingSign(address,res)
	fmt.Println(verifyRES)
}



func TestVerifyRingSign(t *testing.T) {
	msg:="0x68667be06e8e514ffba46b30b9724ae11e3fe0d3"
	ringsig:="0x041147c0340da310b89c45f6c4e60cfc0be9f30d8ba53399e53825abb3d86841f4ce296747bd4e340c04b72df6d1895466e4bff4e1047c8819c5ccbdfd1d77d486&0x041955657dfff9c3faf961ec06d25eb9347d82d7f566b180fe92dc255edaec989c23ad5f7a9329f10e7a628d9a944845c8d1fc1eb0aa6e0305981d64990a4b7084&0x04f2026857f3708d66acb5fdfd9079644fc58ccf0008c427898585478af19ea4752125582144579c8be99f8f5bc2eb39dc5ea6fd9917ed558a489d7894780c0b18&0x0409a2c85b6cefdb40d2376aaaf7834da865adf0db9da43f53d1c5cc2b3838c9b2d454cdfc809c903b3e9a8222727d0720dd37be6138854417b25721a8572cc670&0x04ca5e22db23e0ba56f8f977eaddfdd4441babc5584cf0c636cbb1239e2b75a6055d58a592990d2ed850f22d44b8d9da5c3328aba64038ca595c35466aca17636b&0x041147c0340da310b89c45f6c4e60cfc0be9f30d8ba53399e53825abb3d86841f4ce296747bd4e340c04b72df6d1895466e4bff4e1047c8819c5ccbdfd1d77d486+0x04c7b7aefec8e61f5ca67529cc114f20d80b872e17948704824a32dacedbe26b8b1fd0ab8e0ee8b7320f94f5a6536e922e06111e07ef1d80b5995ad005f862603c+0x871c7963fe74ed6ebe4fd9ef9c39fa09be6df97d90e44b3bce140164aa94d60a&0x37763dbed62be46480888af3a315401cd9e9eff9196f8bc4ef00880317617e4c&0x8d83c1596a197fb9dbc1522b6c5bffa133e17b908e5897c3f20f46ce10fdd160&0xca4ea4f43600de75c1b86ef3ba5da811037a0802dd6226cfc694cf091164e4b8&0xcaf0ffce21cee803a1304d3eea0d33783f712f9375e1e9c27ee1c9b1d901fee8&0xd8d4266e7d6e959bb571012d3d5b417f1715358da7c66d59b4afa8e92900c4c0+0xf89257fc16b1ff4e916e921264081f8ad4771c8cdac82d6c0ff6900645ab718b&0x71589706110259e0597e48f51cf48edb10e7aa1b1fa130ba831182f9d7de7f11&0xdb6d9b302ec0d6b2ee43e8a38955e4e52abe835b4ac6f9f0f212ec8a9ec17bd3&0x7023c1fd3b9251b07f797b79a72b652769430572923d32acad45a8267464ed7b&0xaab29f05aec59d738d412cc6d41fe6affe3ff27e6f3d9b588b5ae8fd1b383a34&0x1ef87b1879ae1bccf136877deea878f4974b6cfbef8b3e380010487fa21b136c"
	msg1,_ := hexutil.Decode(msg)
	msg2 := Keccak256(msg1)

	err,publickeys,keyimage,c,r:=DecodeRingSignOut(ringsig)
	if err !=nil {
		fmt.Println("false")
	}
	fmt.Println(publickeys)

	//fmt.Println("publickeys2",publickeys)
	//fmt.Println("keyimage2",keyimage)
	fmt.Println("c",c)
	fmt.Println("r",r)

	verifyRES:=verifyRingSign(msg2,publickeys,keyimage,c,r)
	fmt.Println(verifyRES)
}

/*
key_______________ &{{0xc420072330 79630083301460742161365576532170812092324123412265315911719269261515424653651 112476271516315044464702925221453141189672530334004419034010603501212342524575} 103942689059836797943162718335431301772098349726577275637088850078609246957897}
private-----> e5cd7a27cc204e8afcc7d7e6f9a0f8a6a51cf859caee758a8b727ab898d2b149
pub------> 0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f

key_______________ &{{0xc420072330 112196137976992462575443469044710133421443743005014286651137628549851680988917 40466401228670625285208411519763252019489565338202778417881329804786451965013} 79361126369370876032448237117094839303182256440582887639513903148208271518019}
private-----> af74ce448c2a603a25cf61ed4265d1306217bec3f0122ce27d217cba0d51e943
pub------> 0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455


key_______________ &{{0xc420072330 73939223911936718389508811230351517873324167471454104359352142886492745844854 107306501457241177390959063288213765951463082684889807094521306712823207290556} 27052755211024503747766097767406729876906031976500417853540542917691177108697}
private-----> 3bcf511c37bd5625189678893b41c0741f9f69a868affb7035c585f9bff304d9
pub------> 0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc

key_______________ &{{0xc420072330 77064954097886753602740786168824050376066187275628318224011504397091435942089 57832376174682959923215965217267997145789318045532593175974951284692875401194} 28481377663979618826420285879396433987143934840891074727561123066211641856150}
private-----> 3ef7e3741ce37046931ff7cfc50d004ba5a31cedd440c1fb28f9f1e851481096
pub------> 0x04aa6137e16c5a56b8cbf9216c4ca79e1502a9997e3882dcff33a5aefe501390c97fdbf70628f78b235aa02bb60fe23d29d32d3a856fb0bd4469a2b69ab5f2d7ea


msg---> 0xb22d14953ae6f086dbf4060f7856c39d1600a964847a27586067c97f72bbf7b3
0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc&0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f+0x04579fc893d0d93987ac2e61aa9459909f8bb05757895fecde0fffa71ffbe7f20c8febfd852476cb581305bf83f32b118ec6166df7341eed4109b3b504d9f877af+0xd9d7e142dc780933908d87be9ce3735ae0e56606cc6ce1aad963d5692d7e292f&0x77305526be63c03e5171c1b5ede6e0f6a3f57a3596ebf1f55f21e2e4adaf3a97&0xed9a38f4afb45019cb12777c378ae1555374ee5192789c8877b89ef7f0eb6f36&0xc1f86ed66637ed7ff2bb6dd297eb8b1a99a35f14f45b913471854465ebc4ed86+0x34b7887cd4b6871841006ca00a0d61a102cc0db48cbd66a98675c14fda6c6d6c&0x448e4a11fd9e963035d7c33f44d7b39d305fbfe105519b304cd52abb48879935&0x975b9debad631c7d9c00196cdc04e76eb6af9f1295f3578e06aa0a4ed9a544f7&0x51c87f81ec510ab17e444c05c8a937702bc699a390e10c259a63260a726d4aff


msg---> 0xb22d14953ae6f086dbf4060f7856c39d1600a964847a27586067c97f72bbf7b3
0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f&0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc&0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&0x04aa6137e16c5a56b8cbf9216c4ca79e1502a9997e3882dcff33a5aefe501390c97fdbf70628f78b235aa02bb60fe23d29d32d3a856fb0bd4469a2b69ab5f2d7ea+0x04e3a9fb126c2710036a9b62d8dafbe4811244b5689bc01054be57059966882d055a58579a8f23677e32550b77a4634410252cb03dcebcab8692c33a0d9655b2be+0x6b5512b0f3d009ab43391bf311eca32fdcf2906dcd2453be26be854d5c2d0ad2&0x787cb1703c1f092ee040a5b7a14c01f05b21c5d609e15c77358becc9efdfe16&0x1552139d25c59149bb9ad5a202cc12b2b7d005e9b575347825e942682d0e2e21&0xaf16d081bcdd2d5613dfa665878fb44c5d69d461d75bee9b875e760ca10ac008+0x64beb295e9365d0cbdd685813e0fe9fb30033bd47544b5df82117fe3b7e6f522&0x31b1b2288438c86e0dc6c02c3b55c174cde2a4d8d4e297bc5ae34f7704cb5798&0x9eef9ffbc335d449da1c79f89c82e8af0eba4b4205a71df62ff374e8bdfb08f&0x1bd6065bce22c844fab1406fc875a93662f54ca739837bdf86397df009324684

0x04e3a9fb126c2710036a9b62d8dafbe4811244b5689bc01054be57059966882d055a58579a8f23677e32550b77a4634410252cb03dcebcab8692c33a0d9655b2be




0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc&0x04aa6137e16c5a56b8cbf9216c4ca79e1502a9997e3882dcff33a5aefe501390c97fdbf70628f78b235aa02bb60fe23d29d32d3a856fb0bd4469a2b69ab5f2d7ea&0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f+0x04e3a9fb126c2710036a9b62d8dafbe4811244b5689bc01054be57059966882d055a58579a8f23677e32550b77a4634410252cb03dcebcab8692c33a0d9655b2be+0xfc8133b2eb17c460b3b09874e70641a937a0f2d076a2d260613cd7d039783600&0xad787f32e8bce7afca2a85fa64fc7ccfe9e3a3b38c07581bd7929abb80c9216b&0x21831cc97b5c57a77c5a98c5cfce2b30ae4fffccd34c22caa05deb46cee48de8&0xedd1ba828192f211021cf8bcf2cca872323f873dd1857c738d3a7f83e84a3726+0x381577c968c7878720bf3ce0cc5b79d24a15e8925ca23279a5edfec55e97ef84&0x311565da543d27d5d96fe071d0804b40b84751ab2f5a4607608089ddbf24e29c&0x117d4214fab3661437851ae14f340165316302751cf9257430db1bbc06487195&0x262c81e0bea6bb85c4e97e6ad219c95a01e831417a58c0c6d615aa2b03949485




pkStr:
0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc&
0x04aa6137e16c5a56b8cbf9216c4ca79e1502a9997e3882dcff33a5aefe501390c97fdbf70628f78b235aa02bb60fe23d29d32d3a856fb0bd4469a2b69ab5f2d7ea&
0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&
0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f+


keyimage:
0x04e3a9fb126c2710036a9b62d8dafbe4811244b5689bc01054be57059966882d055a58579a8f23677e32550b77a4634410252cb03dcebcab8692c33a0d9655b2be+


wStr:
0x5f1929b7d16d1dadc5ea4c9cf2d8e4ec54b18e46ed700684d15ad00132e6a735&0xa3b63397433c15e7ad578f32ed6db7f1e16e357d995ecf406d8dee65ea159918&
0xe1376b161d18c2dcf3089ffb58cf2e44c56f7f5ac19af2f2a9c04007a26d1d7&0x331ca5621782637b971ad441731f7846bc7677bc2734cc0b390566287ddb44e2+


qStr:
0x39cf714efeeea71b12779788fa8173a6c2ea319fa83eb0b17acf9ba4e3e11557&0x32728e37e8cddbf072ca6dba18bedbcca6a13316978537d09c886c827e15ff87&
0xf7779b3008b1e55beff7c3f48c1d643ad6e9ce1a7ec8c3319bf1db43b8ecaa73&0xbc985fb6b4250ee282ef0cd00992d0b94960bd0b1c793ad01e2085bd79922813

*/

