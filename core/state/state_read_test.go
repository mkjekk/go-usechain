package state

import (
	"fmt"
	"github.com/usechain/go-usechain/ethdb"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"testing"
)
func TestGetPublicKeySet(t *testing.T) {

	var(
		db, _      = ethdb.NewMemDatabase()
		//db = core.TxPool{}
		statedb, _ = New(common.Hash{}, NewDatabase(db))
	)

	contractAddr:="0x1e0a480e121ee21f1f7b349d5aedbe6dff46b390"
	contractAddress:=common.HexToAddress(contractAddr)
	key:="0xbccc714d56bc0da0fd33d96d2a87b680dd6d0df6"
	var pos uint =0

	//1.variable
	v1,err:=QueryDataFromStateDb(statedb,contractAddress,testMethod,key,pos)
	if err !=nil {
		fmt.Println("query error:",err)
	}
	v11:=hexutil.Encode(v1[:])
	fmt.Println("v11:::::", v11)
	fmt.Println("/////////////////////////////////////////////////////////////////////")
	//
	////2.address
	//key2:="0xa2f6c9229346f72c038e09ea8f9b3133403018ce"
	//var pos2 uint = 1
	//v2,err:=QueryDataFromStateDb(statedb,contractAddress,OneTimeAddr,key2,pos2)
	//if err !=nil {
	//	fmt.Println("query error:",err)
	//}
	//fmt.Println("v2:::",v2)
	//fmt.Println("/////////////////////////////////////////////////////////////////////")
	//
	////3.publickey
	//key3:="0xa2f6c9229346f72c038e09ea8f9b3133403018ce"
	//var pos3 uint =2
	//v3,err:=QueryDataFromStateDb(statedb,contractAddress,OneTimeAddr,key3,pos3)
	//fmt.Println(v3)
	//if err !=nil {
	//	fmt.Println("query error:",err)
	//}
	//fmt.Println("v3:::::",v3)

}
