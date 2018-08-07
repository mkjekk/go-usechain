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
//
// Author: lyszhang
// Time:   2018/07/11
// Description: Committee read ABaccount verify info, scan the accounts & change the AB account verify stat
//    		 		A1 = [hash(bA)]G + S = [hash(aB)]G + S
//			 	And have move the ringSig check part to tx validate check round, the committee's work is read the AB account
//			 	verify request, scan it and check the state

package main

import (
	"fmt"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/commitee/committee-demo/contract"
	"github.com/usechain/go-usechain/common"
	//"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/common/hexutil"
)

func main() {
	ringSig := "0x3078303462303064303761623964383433653133373565613432643133656138663330663937333432373935333239666535393733323831383232303932636465313533663861623530346432356134383837646436376139653131316635613832346565396562323463653539633963336430396430376166323937353539396139662630783034613337383165323131636232616431316538643938623130656163303534393639653531316661636139386532326536386566653732643230373331343837366564336435336438323362346337346439313136313963313835346634613766636534383131643038363039396131353539313165663136613339376536626326307830346638306363333832616432353461346139346231356162663063323761663739393333666530346366646461316166383739373234346163306337356465663535393737326265333535663038316264316261313436363433656664623266613462353338613538376631373365663663333733316165633431373536343535263078303461613631333765313663356135366238636266393231366334636137396531353032613939393765333838326463666633336135616566653530313339306339376664626637303632386637386232333561613032626236306665323364323964333264336138353666623062643434363961326236396162356632643765612b3078303465336139666231323663323731303033366139623632643864616662653438313132343462353638396263303130353462653537303539393636383832643035356135383537396138663233363737653332353530623737613436333434313032353263623033646365626361623836393263333361306439363535623262652b30783662353531326230663364303039616234333339316266333131656361333266646366323930366463643234353362653236626538353464356332643061643226307837383763623137303363316630393265653034306135623761313463303166303562323163356436303965313563373733353862656363396566646665313626307831353532313339643235633539313439626239616435613230326363313262326237643030356539623537353334373832356539343236383264306532653231263078616631366430383162636464326435363133646661363635383738666234346335643639643436316437356265653962383735653736306361313061633030382b3078363462656232393565393336356430636264643638353831336530666539666233303033336264343735343462356466383231313766653362376536663532322630783331623162323238383433386338366530646336633032633362353563313734636465326134643864346532393762633561653334663737303463623537393826307839656566396666626333333564343439646131633739663839633832653861663065626134623432303561373164663632666633373465386264666230386626307831626436303635626365323263383434666162313430366663383735613933363632663534636137333938333762646638363339376466303039333234363834"
	pubSkey := "0x0364c17a83c37aa08f7e61005026ea0034f87ba0bf00ddb85b642ad92f532661cf021a9598f1801120feed6dc770ceebaa463f89aec49e4dcffaf408e0dfae979347"

	for i := 0; true; i++ {
		fmt.Println("::::::::::::::::::Connecting::::::::::::::::")

		//A1, S1 := contract.ReadUnverifiedAccount()
		b := contract.ReadCommitteePrivatekey()
		//MainAccount := contract.Rea//dMainAccount()
		data, _ := hexutil.Decode(ringSig)
		_, mainAccount, _, _, _ :=crypto.DecodeRingSignOut(string(data))  			   //Main Array get
		fmt.Println(mainAccount[0])

		data, _ = hexutil.Decode(pubSkey)
		fmt.Printf("%s\n", data)
		A1, S1, _ := keystore.GeneratePKPairFromABaddress(data)  // Get

		for i := range mainAccount {
			fmt.Println(i)
			A := mainAccount[i]
			A1Recovery := crypto.ScanA1(b,  A, S1)
			fmt.Println("A1' : ", A1Recovery)
			fmt.Println("A1  : ", A1)
			if string(crypto.FromECDSAPub(&A1Recovery)) == string(crypto.FromECDSAPub(A1)) {
				fmt.Println(":::::::success")
				data := contract.GenerateConfirmAccountData(1,1)
				err := contract.SendRequestToContract(common.AuthenticationContractAddressString, data)
				if err != nil {
					log.Error("The request failed, pls check the usechain node running stat")
				}
			}
		}
		break
	}
}