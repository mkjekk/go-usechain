// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"fmt"
	"github.com/usechain/go-usechain/common"
	"encoding/hex"
	"errors"
	"github.com/usechain/go-usechain/crypto/sha3"
	"math/big"
	"time"
	"math/rand"
	"unsafe"
	"reflect"
)

const (
	HashLength = 32
)

// storjFlag defined the type of query data
type storjFlag struct {
	index 		int
	parameter 	int
	methodType	string
}

// a list type of query data from stateDB
var (
	// len of confirmed one time address
	OneTimeAddrConfirmedLenIndex = storjFlag{
		index:3,
		parameter:0,
		methodType:"uintValue",
	}
	// len of confirmed main address
	ConfirmedMainAddressLenIndex = storjFlag{
		index:4,
		parameter:0,
		methodType:"uintValue",
	}
	// len of confirmed sub address
	ConfirmedSubAddressLenIndex = storjFlag{
		index:5,
		parameter:0,
		methodType:"uintValue",
	}
	// len of unconfirmed address
	UnConfirmedAddressLen = storjFlag{
		index:6,
		parameter:0,
		methodType:"uintValue",
	}
	// check the committee address info
	IsCommittee = storjFlag{
		index:7,
		parameter:2,
		methodType:"mappingAddrToStruct",
	}
	// committee address listweiy
	CMMTTEEs = storjFlag{
		index:8,
		parameter:15,
		methodType:"listValue",
	}
	// public key of each committee
	CommitteePublicKey = storjFlag{
		index:9,
		parameter:0,
		methodType:"mappingAddrToString",
	}
	// mapping cert id to address
	CertToAddress = storjFlag{
		index:10,
		parameter:2,
		methodType:"mappingUintToStruct",
	}
	// confirmation of a committee
	CommitteeConfirmations = storjFlag{
		index:11,
		parameter:0,
		methodType:"mappingToMapping",
	}
	// each one time address's info
	OneTimeAddr = storjFlag{
		index:12,
		parameter:4,
		methodType:"mappingAddrToStruct",
	}
	// check if one time address confirmed
	OneTimeAddrConfirmed = storjFlag{
		index:13,
		parameter:0,
		methodType:"listValue",
	}
	// query main/sub address info
	CertificateAddr = storjFlag{
		index:14,
		parameter:6,
		methodType:"mappingAddrToStruct",
	}
	// confirmed main address list
	ConfirmedMainAddress = storjFlag{
		index:15,
		parameter:0,
		methodType:"listValue",
	}
	// confirmed sub address list
	ConfirmedSubAddress = storjFlag{
		index:16,
		parameter:0,
		methodType:"listValue",
	}
	// unconfirmed address list
	UnConfirmedAddress = storjFlag{
		index:17,
		parameter:0,
		methodType:"listValue",
	}
)
// main entrance of query data from contract statedb, you can see details from our wiki
func QueryDataFromStateDb(statedb *StateDB, contractAddress common.Address, method storjFlag, key string,pos int64) ([]byte, error) {
	// generate a query index
	keyIndex, err := ExpandToIndex(method, key, pos)
	if err != nil {
		fmt.Println(err)
	}
	// get data from the contract statedb
	res := statedb.GetState(contractAddress, common.HexToHash(keyIndex))
	return res[:], nil
}

// using method key & pos generate a query index
// methods: get index from storjFlag
// key: parameter of storage type
// pos: index of state variable
func ExpandToIndex(methods storjFlag, key string, pos int64) (string, error) {
	// change "key" to string type
	newKey := string(FromHex(key))
	// init a byte slice of hash lengths
	indexed := make([]byte,common.HashLength)
	// fill data to indexed byte slice from method index
	indexed[len(indexed)-1] = byte(methods.index)
	// change byte slice to string type
	newIndex := hex.EncodeToString(indexed)

	switch methods.methodType {
	// if the method is "uintValue", return the string data
	case "uintValue":
		return newIndex, nil

	case "mappingAddrToStruct":
		// expand prefix of new key, length is 32 Byte
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		// calculate statedb index from newKey
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		// return data that has been added to the pos
		return IncreaseHexByNum(indexKey, pos), nil

	case "mappingAddrToString":
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		return hex.EncodeToString(indexKey), nil

	case "mappingUintToStruct":
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		return IncreaseHexByNum(indexKey, pos), nil
	// not working yet
	case "mappingToMapping":
		return "", errors.New("method is not working yet")

	case "listValue":
		if key != "" {
			key = ""
		}
		indexKey := CalculateStateDbIndex(key, newIndex)
		return IncreaseHexByNum(indexKey, pos), nil
	}
	return "", errors.New("no method matched")
}

// extend the len of key
func ExtendPrefix(key string, num int) string {
	preZero := ""
	for i := 0; i < num; i++ {
		preZero += "0"
	}
	key = preZero + key
	return key
}

// change key's type to string
func FromHex(key string) string {
	if key == "" {
		return key
	}
	if key[0:2] == "0x" || key[0:2] == "0X" {
		key = key[2:]
	}
	if len(key) %2 == 1 {
		key = "0" + key
	}
	return key
}

// return the string data that has been added to the num
func IncreaseHexByNum(indexKeyHash []byte, num int64) string {
	x := big.NewInt(0)
	y := big.NewInt(int64(num))
	x.SetBytes(indexKeyHash)
	x.Add(x, y)
	return hex.EncodeToString(x.Bytes())
}

// calculate the statedb index from key and parameter
func CalculateStateDbIndex(key string, paramIndex string) []byte {
	web3key := key + paramIndex
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	hash.Write(decodeHexFromString(web3key))
	keyIndex = hash.Sum(keyIndex)
	return keyIndex
}

// decode string data to hex
func decodeHexFromString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// generate a random number from a range
func GenerateRandomNumber(numRange int64) int64 {
	seed := time.Now().UnixNano()
	src := rand.NewSource(seed)
	randNum := rand.New(src)
	return randNum.Int63n(numRange)
}

// get byte data length
func GetLen(lenByte []byte) int64 {
	b := big.NewInt(0)
	b.SetBytes(lenByte)
	return b.Int64()
}


func BytesToString(byteData []byte) string {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&byteData))
	sh := reflect.StringHeader{bh.Data, bh.Len}
	return *(*string)(unsafe.Pointer(&sh))
}
