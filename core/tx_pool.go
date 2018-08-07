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

package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"crypto/rand"
	"encoding/binary"
	db "github.com/syndtr/goleveldb/leveldb"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/ecies"
	"github.com/usechain/go-usechain/event"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/metrics"
	"github.com/usechain/go-usechain/params"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
	"reflect"
	"strings"
	"github.com/usechain/go-usechain/accounts/abi"
	"github.com/usechain/go-usechain/common/hexutil"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	// rmTxChanSize is the size of channel listening to RemovedTransactionEvent.
	rmTxChanSize = 10
)

var (
	// ErrInvalidSender is returned if the transaction contains an invalid signature.
	ErrInvalidSender = errors.New("invalid sender")

	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrUnderpriced is returned if a transaction's gas price is below the minimum
	// configured for the transaction pool.
	ErrUnderpriced = errors.New("transaction underpriced")

	// ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
	// with a different one without the required price bump.
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")

	// ErrInvalidAuthenticationsig is returned if the authentication signature is invaild
	ErrInvalidAuthenticationsig = errors.New("invalid authentication signature")

	// ErrAuthenticationDuplicate is returned if the authentication been duplicated
	ErrAuthenticationDuplicated = errors.New("authentication duplicated, the address has already certificated")

	// ErrIllegalAddress is returned if the tx source&dest addr is illegal
	ErrIllegalAddress = errors.New("illegal address, pls do the authentication or becareful about the dest addr")

	// ErrIllegalDestAddress is returned if the tx dest addr is illegal
	ErrIllegalDestAddress = errors.New("illegal destination address")

	// ErrIllegalSourceAddress is returned if the tx source addr is illegal
	ErrIllegalSourceAddress = errors.New("illegal source address")

	// ErrIntrinsicGas is returned if the transaction is specified to use less gas
	// than required to start the invocation.
	ErrIntrinsicGas = errors.New("intrinsic gas too low")

	// ErrGasLimit is returned if a transaction's requested gas limit exceeds the
	// maximum allowance of the current block.
	ErrGasLimit = errors.New("exceeds block gas limit")

	// ErrNegativeValue is a sanity error to ensure noone is able to specify a
	// transaction with a negative value.
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
)

var (
	evictionInterval    = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval = 8 * time.Second // Time interval to report transaction pool stats
)

var (
	// Metrics for the pending pool
	pendingDiscardCounter   = metrics.NewRegisteredCounter("txpool/pending/discard", nil)
	pendingReplaceCounter   = metrics.NewRegisteredCounter("txpool/pending/replace", nil)
	pendingRateLimitCounter = metrics.NewRegisteredCounter("txpool/pending/ratelimit", nil) // Dropped due to rate limiting
	pendingNofundsCounter   = metrics.NewRegisteredCounter("txpool/pending/nofunds", nil)   // Dropped due to out-of-funds

	// Metrics for the queued pool
	queuedDiscardCounter   = metrics.NewRegisteredCounter("txpool/queued/discard", nil)
	queuedReplaceCounter   = metrics.NewRegisteredCounter("txpool/queued/replace", nil)
	queuedRateLimitCounter = metrics.NewRegisteredCounter("txpool/queued/ratelimit", nil) // Dropped due to rate limiting
	queuedNofundsCounter   = metrics.NewRegisteredCounter("txpool/queued/nofunds", nil)   // Dropped due to out-of-funds

	// General tx metrics
	invalidTxCounter     = metrics.NewRegisteredCounter("txpool/invalid", nil)
	underpricedTxCounter = metrics.NewRegisteredCounter("txpool/underpriced", nil)
)

// TxStatus is the current status of a transaction as seen by the pool.
type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota
	TxStatusQueued
	TxStatusPending
	TxStatusIncluded
)

const (
	defaultKeystoreDict    = ""
	defaultGasForCommittee = 1000000
	DefaultReplayMsg       = "0xeeeeeeee"
	DefaultSendTagMsg      = "0xffffffff"
	TextAddress1           = "0xd2a132139ca63447a7affc49143c17bf81948d54"
	TextAddress2           = "0xfa01c38d39625a76d2f13af3203e82555236f9ea"

)

var priv string = "113b218c583e05d08130e04ddd9ff852095e3352ca79b0249385ce438035b3af"
var privateKeyECDSA_text, _ = crypto.HexToECDSA(priv)

var replayCh = make(chan common.Hash)

// blockChain provides the state of blockchain and current gas limit to do
// some pre checks in tx pool and event subscribers.
type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// TxPoolConfig are the configuration parameters of the transaction pool.
type TxPoolConfig struct {
	NoLocals  bool          // Whether local transaction handling should be disabled
	Journal   string        // Journal of local transactions to survive node restarts
	Rejournal time.Duration // Time interval to regenerate the local transaction journal

	PriceLimit uint64 // Minimum gas price to enforce for acceptance into the pool
	PriceBump  uint64 // Minimum price bump percentage to replace an already existing transaction (nonce)

	AccountSlots uint64 // Minimum number of executable transaction slots guaranteed per account
	GlobalSlots  uint64 // Maximum number of executable transaction slots for all accounts
	AccountQueue uint64 // Maximum number of non-executable transaction slots permitted per account
	GlobalQueue  uint64 // Maximum number of non-executable transaction slots for all accounts

	Lifetime time.Duration // Maximum amount of time non-executable transaction are queued
}

// DefaultTxPoolConfig contains the default configurations for the transaction
// pool.
var DefaultTxPoolConfig = TxPoolConfig{
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	PriceLimit: 1,
	PriceBump:  10,

	AccountSlots: 16,
	GlobalSlots:  4096,
	AccountQueue: 64,
	GlobalQueue:  1024,

	Lifetime: 3 * time.Hour,
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (config *TxPoolConfig) sanitize() TxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid txpool price limit", "provided", conf.PriceLimit, "updated", DefaultTxPoolConfig.PriceLimit)
		conf.PriceLimit = DefaultTxPoolConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultTxPoolConfig.PriceBump)
		conf.PriceBump = DefaultTxPoolConfig.PriceBump
	}
	return conf
}

// TxPool contains all currently known transactions. Transactions
// enter the pool when they are received from the network or submitted
// locally. They exit the pool when they are included in the blockchain.
//
// The pool separates processable transactions (which can be applied to the
// current state) and future transactions. Transactions move between those
// two states over time as they are received and processed.
type TxPool struct {
	config       TxPoolConfig
	chainconfig  *params.ChainConfig
	chain        blockChain
	gasPrice     *big.Int
	txFeed       event.Feed
	scope        event.SubscriptionScope
	chainHeadCh  chan ChainHeadEvent
	chainHeadSub event.Subscription
	signer       types.Signer
	mu           sync.RWMutex

	currentState  *state.StateDB      // Current state in the blockchain head
	pendingState  *state.ManagedState // Pending state tracking virtual nonces
	currentMaxGas uint64              // Current gas limit for transaction caps

	locals  *accountSet // Set of local transaction to exempt from eviction rules
	journal *txJournal  // Journal of local transaction to back up to disk

	pending map[common.Address]*txList         // All currently processable transactions
	queue   map[common.Address]*txList         // Queued but non-processable transactions
	beats   map[common.Address]time.Time       // Last heartbeat from each known account
	all     map[common.Hash]*types.Transaction // All transactions to allow lookups
	priced  *txPricedList                      // All transactions sorted by price

	wg sync.WaitGroup // for shutdown sync

	homestead      bool
	accountManager *accounts.Manager
}

// NewTxPool creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
func NewTxPool(config TxPoolConfig, chainconfig *params.ChainConfig, chain blockChain, manager *accounts.Manager) *TxPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	pool := &TxPool{
		config:         config,
		chainconfig:    chainconfig,
		chain:          chain,
		signer:         types.NewEIP155Signer(chainconfig.ChainId),
		pending:        make(map[common.Address]*txList),
		queue:          make(map[common.Address]*txList),
		beats:          make(map[common.Address]time.Time),
		all:            make(map[common.Hash]*types.Transaction),
		chainHeadCh:    make(chan ChainHeadEvent, chainHeadChanSize),
		gasPrice:       new(big.Int).SetUint64(config.PriceLimit),
		accountManager: manager,
	}
	pool.locals = newAccountSet(pool.signer)
	pool.priced = newTxPricedList(&pool.all)
	pool.reset(nil, chain.CurrentBlock().Header())

	// If local transactions and journaling is enabled, load from disk
	if !config.NoLocals && config.Journal != "" {
		pool.journal = newTxJournal(config.Journal)

		if err := pool.journal.load(pool.AddLocal); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
	}
	// Subscribe events from blockchain
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)

	// Start the event loop and return
	pool.wg.Add(1)
	go pool.loop()

	return pool
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and transaction eviction tickers
	var prevPending, prevQueued, prevStales int

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	journal := time.NewTicker(pool.config.Rejournal)
	defer journal.Stop()

	// Track the previous head headers for transaction reorgs
	head := pool.chain.CurrentBlock()

	// Keep waiting for and reacting to the various events
	for {
		select {
		// Handle ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.mu.Lock()
				if pool.chainconfig.IsHomestead(ev.Block.Number()) {
					pool.homestead = true
				}
				pool.reset(head.Header(), ev.Block.Header())
				head = ev.Block

				pool.mu.Unlock()
			}
		// Be unsubscribed due to system stopped
		case <-pool.chainHeadSub.Err():
			return

		// Handle stats reporting ticks
		case <-report.C:
			pool.mu.RLock()
			pending, queued := pool.stats()
			stales := pool.priced.stales
			pool.mu.RUnlock()

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				prevPending, prevQueued, prevStales = pending, queued, stales
			}

		// Handle inactive account transaction eviction
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				// Skip local transactions from the eviction mechanism
				if pool.locals.contains(addr) {
					continue
				}
				// Any non-locals old enough should be removed
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					for _, tx := range pool.queue[addr].Flatten() {
						pool.removeTx(tx.Hash())
					}
				}
			}
			pool.mu.Unlock()

		// Handle local transaction journal rotation
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local tx journal", "err", err)
				}
				pool.mu.Unlock()
			}
		}
	}
}

// lockedReset is a wrapper around reset to allow calling it in a thread safe
// manner. This method is only ever used in the tester!
func (pool *TxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.reset(oldHead, newHead)
}

// reset retrieves the current state of the blockchain and ensures the content
// of the transaction pool is valid with regard to the chain state.
func (pool *TxPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	var reinject types.Transactions

	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Debug("Skipping deep transaction reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			var discarded, included types.Transactions

			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			for rem.Hash() != add.Hash() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			reinject = types.TxDifference(discarded, included)
		}
	}
	// Initialize the internal state to the current head
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header() // Special case during testing
	}
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.pendingState = state.ManageState(statedb)
	pool.currentMaxGas = newHead.GasLimit

	// Inject any transactions discarded due to reorgs
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	pool.addTxsLocked(reinject, false)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another transaction (e.g.
	// higher gas price)
	pool.demoteUnexecutables()

	// Update all accounts to the latest known pending nonce
	for addr, list := range pool.pending {
		txs := list.Flatten() // Heavy but will be cached and is needed by the miner anyway
		pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
	}
	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	pool.promoteExecutables(nil)
}

// Stop terminates the transaction pool.
func (pool *TxPool) Stop() {
	// Unsubscribe all subscriptions registered from txpool
	pool.scope.Close()

	// Unsubscribe subscriptions registered from blockchain
	pool.chainHeadSub.Unsubscribe()
	pool.wg.Wait()

	if pool.journal != nil {
		pool.journal.close()
	}
	log.Info("Transaction pool stopped")
}

// SubscribeTxPreEvent registers a subscription of TxPreEvent and
// starts sending event to the given channel.
func (pool *TxPool) SubscribeTxPreEvent(ch chan<- TxPreEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// GasPrice returns the current gas price enforced by the transaction pool.
func (pool *TxPool) GasPrice() *big.Int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return new(big.Int).Set(pool.gasPrice)
}

// SetGasPrice updates the minimum price required by the transaction pool for a
// new transaction, and drops all transactions below this threshold.
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.gasPrice = price
	for _, tx := range pool.priced.Cap(price, pool.locals) {
		pool.removeTx(tx.Hash())
	}
	log.Info("Transaction pool price threshold updated", "price", price)
}

// State returns the virtual managed state of the transaction pool.
func (pool *TxPool) State() *state.ManagedState {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingState
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.stats()
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) stats() (int, int) {
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	return pending, nil
}

// local retrieves all currently known local transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...)
		}
	}
	return txs
}

//check the certificate signature if the transaction is authentication Tx
func checkAddrLegality(_db *state.StateDB, tx *types.Transaction, _from common.Address) error {
	///TODO: remove the legality check, update it later
	/*
		if _db.CheckAddrAuthenticateStat(_from) == 0 {
			return ErrIllegalSourceAddress
		}

		//Need check dest addr only except contract creation
		if tx.To() != nil {
			if _db.CheckAddrAuthenticateStat(*tx.To()) == 0 && _db.GetCode(*tx.To()) == nil {
				return ErrIllegalDestAddress
			}
		}
	*/
	fmt.Println("The normal transaction addr checking passed!")

	return nil
}

//check the certificate signature if the transaction is multiAccount authentication Tx
//   MultiAB account authentication TX:
//   -------------------------------------------------------------------
//  |             |              |               |                      |
//  |   ABI_tag   |   ringSig    |   pub_S_key   |   publicKeyMirror    |
//  |             |              |               |                      |
//   -------------------------------------------------------------------
//  ======================================================================
func checkMultiAccountSig(tx *types.Transaction, _db *state.StateDB, _addType int, _from common.Address) error {
	/*
	return nil
	//get first parameter start position
	ringsigPosition := binary.BigEndian.Uint16(tx.Data()[34:36])
	//get second parameter start position
	pubPosition := binary.BigEndian.Uint16(tx.Data()[66:68])
	//get third parameter start position
	pubMirrorPosition := binary.BigEndian.Uint16(tx.Data()[98:100])

	//get ringsign length
	ringsigLen := binary.BigEndian.Uint16(tx.Data()[ringsigPosition+34 : (ringsigPosition + 36)])
	//get pubkey length
	pubLen := binary.BigEndian.Uint16(tx.Data()[pubPosition+34 : (pubPosition + 36)])
	//get CA length
	pubMirrorLen := binary.BigEndian.Uint16(tx.Data()[pubMirrorPosition+34 : (pubMirrorPosition + 36)])

	ringsign := tx.Data()[ringsigPosition+36 : ringsigPosition+36+ringsigLen]
	pub := tx.Data()[pubPosition+36 : pubPosition+36+pubLen]
	pubMirror := tx.Data()[pubMirrorPosition+36 : pubMirrorPosition+36+pubMirrorLen]
	*/
	usechainABI, err := abi.JSON(strings.NewReader(common.UsechainABI))
	if err != nil {
		log.Error("usechainABI error")
	}

	method, exist := usechainABI.Methods["storeMainUserCert"]
	if !exist {
		log.Error("method storeMainUserCert not found")
	}

	InputDataInterface,err :=method.Inputs.UnpackABI(tx.Data()[4:])
	if err !=nil {
		fmt.Println("method.Inputs: ",err)
		return err
	}

	var inputData []string
	for _, param := range InputDataInterface {
		inputData = append(inputData, param.(string))
	}

	ringsign := inputData[0]
	//pub := inputData[1]
	pubMirror := inputData[2]


	msg:=hexutil.Encode(_from[:])
	fmt.Println("msg---->",msg)
	fmt.Println("ringsign-->",ringsign)

	ringRes:=crypto.VerifyRingSign(msg, ringsign)
	if ringRes == false {
		return errors.New("verify ring signature error")
	}
	fmt.Println("ringRes------->",ringRes)

	err, pubKeys, pubMirrorKey, _, _ := crypto.DecodeRingSignOut(ringsign)
	if err != nil {
		log.Error("The  ringSig decode failed")
		return err
	}

	fmt.Println(pubKeys)
	fmt.Println(crypto.FromECDSAPub(pubMirrorKey))
	fmt.Println(pubMirror)

	if  common.ToHex((crypto.FromECDSAPub(pubMirrorKey))) != pubMirror {
		log.Error("The pubMirror doesn't match with ringSig")
		return errors.New("the pubMirror doesn't match with ringSig")
	}

	//if !_db.CheckRingSigPubKey(_addType, pubKeys) {
	//	log.Error("The ringSig pubkey is illegal!")
	//	return errors.New("the ringSig pubkey is illegal")
	//}
	return nil
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTx(tx *types.Transaction, local bool) error {
	log.Info("Transaction entered validateTx function")
	// Heuristic limit, reject transactions over 32KB to prevent DOS attacks
	if tx.Size() > 32*1024 {
		return ErrOversizedData
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a transaction using the RPC.
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}

	// Ensure the transaction doesn't exceed the current block limit gas.
	if pool.currentMaxGas < tx.Gas() {
		return ErrGasLimit
	}

	// Make sure the transaction is signed properly
	from, err := types.Sender(pool.signer, tx)
	if err != nil {
		return ErrInvalidSender
	}
	//If the transaction is authentication, check txCert Signature
	//If the transaction isn't, check the address legality
	log.Info("tx.Data()::",tx.Data())

	if tx.IsAuthentication() {
		log.Info("Is a authentication tx")
		err = tx.CheckCertificateSig(from)
		if err != nil {
			return ErrInvalidAuthenticationsig
		}
	} else if tx.IsMainAuthentication() {
		log.Info("Is a Main authentication tx")
		err = checkMultiAccountSig(tx, pool.currentState, common.MainAddress, from)
		if err != nil {
			return ErrInvalidAuthenticationsig
		}
	} else if tx.IsSubAuthentication() {
		log.Info("Is a Sub authentication tx")
		err = checkMultiAccountSig(tx, pool.currentState, common.SubAddress, from)
		if err != nil {
			return ErrInvalidAuthenticationsig
		}
	} else {
		log.Info("Is a normal tx")
		err = checkAddrLegality(pool.currentState, tx, from)
		if err != nil {
			return ErrIllegalAddress
		}
	}

	// Drop non-local transactions under our own minimal accepted gas price
	local = local || pool.locals.contains(from) // account may be local even if the transaction arrived from the network
	if !local && pool.gasPrice.Cmp(tx.GasPrice()) > 0 && !tx.IsAuthentication() {
		return ErrUnderpriced
	}

	log.Info("The transction check successed!")
	// Ensure the transaction adheres to nonce ordering
	if pool.currentState.GetNonce(from) > tx.Nonce() {
		return ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	if pool.currentState.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return ErrInsufficientFunds
	}
	intrGas, err := IntrinsicGas(tx.Data(), tx.To() == nil, pool.homestead)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return ErrIntrinsicGas
	}
	return nil
}

// add validates a transaction and inserts it into the non-executable queue for
// later pending promotion and execution. If the transaction is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added transaction is marked as local, its sending account will be
// whitelisted, preventing any associated transaction from being dropped out of
// the pool due to pricing constraints.
func (pool *TxPool) add(tx *types.Transaction, local bool) (bool, error) {
	log.Info("entered Txpool add function")
	// If the transaction is already known, discard it
	hash := tx.Hash()
	if pool.all[hash] != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		return false, fmt.Errorf("known transaction: %x", hash)
	}
	// If the transaction fails basic validation, discard it
	if err := pool.validateTx(tx, local); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		invalidTxCounter.Inc(1)
		return false, err
	}
	// If the transaction pool is full, discard underpriced transactions
	if uint64(len(pool.all)) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new transaction is underpriced, don't accept it
		if pool.priced.Underpriced(tx, pool.locals) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GasPrice())
			underpricedTxCounter.Inc(1)
			return false, ErrUnderpriced
		}
		// New transaction is better than our worse ones, make room for it
		drop := pool.priced.Discard(len(pool.all)-int(pool.config.GlobalSlots+pool.config.GlobalQueue-1), pool.locals)
		for _, tx := range drop {
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "price", tx.GasPrice())
			underpricedTxCounter.Inc(1)
			pool.removeTx(tx.Hash())
		}
	}
	// If the transaction is replacing an already pending one, do directly
	from, _ := types.Sender(pool.signer, tx) // already validated
	if list := pool.pending[from]; list != nil && list.Overlaps(tx) {
		// Nonce already pending, check if required price bump is met
		inserted, old := list.Add(tx, pool.config.PriceBump)
		if !inserted {
			pendingDiscardCounter.Inc(1)
			return false, ErrReplaceUnderpriced
		}
		// New transaction is better, replace old one
		if old != nil {
			delete(pool.all, old.Hash())
			pool.priced.Removed()
			pendingReplaceCounter.Inc(1)
		}
		pool.all[tx.Hash()] = tx
		pool.priced.Put(tx)
		pool.journalTx(from, tx)

		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())

		// We've directly injected a replacement transaction, notify subsystems
		go pool.txFeed.Send(TxPreEvent{tx})

		return old != nil, nil
	}
	// committee transaction check
	store := pool.accountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	localAccount := store.Accounts()[0]
	localAddress := localAccount.Address

	go func() {
		sender, _ := types.Sender(pool.signer, tx)
		fmt.Printf("in range , the addr now is %x ---- and tx.To() is %x \n", sender, tx.To())
		if tx.To() != nil && pool.currentState.IsCommittee(*(tx.To())) && pool.currentState.IsCommittee(sender) {
			if reflect.DeepEqual(sender, localAddress) {
				tag := tx.Data()[:len(DefaultSendTagMsg)]
				if reflect.DeepEqual(string(tag), DefaultSendTagMsg) {
					fmt.Println("---------- start special tx ----------")
					cryptoMsg := tx.Data()[len(DefaultSendTagMsg):]
					msg, err := AnalyticMsgInfo(cryptoMsg, localAccount, store)
					if err != nil {
						log.Info("some err between AnalyticMsgInfo", err)
					}
					GlobalMsgMapStore(sender, msg, tx.Hash())
					select {
					case <-time.After(20 * time.Second):
						//go ReplayToCommittee(sender, *tx.To(), tx.GasPrice(), pool, tx.Data(), store, msg)
						return
					case <-replayCh:
						fmt.Println("------- received return info -----------")
						return
					}
				}
			} else if reflect.DeepEqual(*tx.To(), localAddress) {
				fmt.Println("---- tx.to is localhost ----")
				tag := tx.Data()[:len(DefaultSendTagMsg)]
				if reflect.DeepEqual(string(tag), DefaultSendTagMsg) {
					fmt.Println("---------- node receive the special tx ----------")
					cryptoMsg := tx.Data()[len(DefaultSendTagMsg):]
					msg, err := AnalyticMsgInfo(cryptoMsg, localAccount, store)
					if err != nil {
						log.Info("some err between AnalyticMsgInfo", err)
					}
					GlobalMsgMapStore(sender, msg, tx.Hash())
					//ReplayToCommitteeOnce(*tx.To(), sender, tx.GasPrice(), pool, tx.Data(), store)
				} else if reflect.DeepEqual(string(tag), DefaultReplayMsg) {
					fmt.Println("------- come into set info in channel -------")
					replayCh <- tx.Hash()
				}
			}
		}
	}()
	// New transaction isn't replacing a pending one, push into queue
	replace, err := pool.enqueueTx(hash, tx)
	if err != nil {
		return false, err
	}
	// Mark local addresses and journal local transactions
	if local {
		pool.locals.add(from)
	}
	pool.journalTx(from, tx)

	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replace, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) enqueueTx(hash common.Hash, tx *types.Transaction) (bool, error) {
	// Try to insert the transaction into the future queue
	from, _ := types.Sender(pool.signer, tx) // already validated
	if pool.queue[from] == nil {
		pool.queue[from] = newTxList(false)
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		queuedDiscardCounter.Inc(1)
		return false, ErrReplaceUnderpriced
	}
	// Discard any previous transaction and mark this
	if old != nil {
		delete(pool.all, old.Hash())
		pool.priced.Removed()
		queuedReplaceCounter.Inc(1)
	}
	pool.all[hash] = tx
	pool.priced.Put(tx)
	return old != nil, nil
}

// journalTx adds the specified transaction to the local disk journal if it is
// deemed to have been sent from a local account.
func (pool *TxPool) journalTx(from common.Address, tx *types.Transaction) {
	// Only journal if it's enabled and the transaction is local
	if pool.journal == nil || !pool.locals.contains(from) {
		return
	}
	if err := pool.journal.insert(tx); err != nil {
		log.Warn("Failed to journal local transaction", "err", err)
	}
}

// promoteTx adds a transaction to the pending (processable) list of transactions.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) {
	// Try to insert the transaction into the pending queue
	if pool.pending[addr] == nil {
		pool.pending[addr] = newTxList(true)
	}
	list := pool.pending[addr]

	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		delete(pool.all, hash)
		pool.priced.Removed()

		pendingDiscardCounter.Inc(1)
		return
	}
	// Otherwise discard any previous transaction and mark this
	if old != nil {
		delete(pool.all, old.Hash())
		pool.priced.Removed()

		pendingReplaceCounter.Inc(1)
	}
	// Failsafe to work around direct pending inserts (tests)
	if pool.all[hash] == nil {
		pool.all[hash] = tx
		pool.priced.Put(tx)
	}
	// Set the potentially new pending nonce and notify any subsystems of the new tx
	pool.beats[addr] = time.Now()
	pool.pendingState.SetNonce(addr, tx.Nonce()+1)

	go pool.txFeed.Send(TxPreEvent{tx})
}

// AddLocal enqueues a single transaction into the pool if it is valid, marking
// the sender as a local one in the mean time, ensuring it goes around the local
// pricing constraints.
func (pool *TxPool) AddLocal(tx *types.Transaction) error {
	return pool.addTx(tx, !pool.config.NoLocals)
}

// AddRemote enqueues a single transaction into the pool if it is valid. If the
// sender is not among the locally tracked ones, full pricing constraints will
// apply.
func (pool *TxPool) AddRemote(tx *types.Transaction) error {
	return pool.addTx(tx, false)
}

// AddLocals enqueues a batch of transactions into the pool if they are valid,
// marking the senders as a local ones in the mean time, ensuring they go around
// the local pricing constraints.
func (pool *TxPool) AddLocals(txs []*types.Transaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals)
}

// AddRemotes enqueues a batch of transactions into the pool if they are valid.
// If the senders are not among the locally tracked ones, full pricing constraints
// will apply.
func (pool *TxPool) AddRemotes(txs []*types.Transaction) []error {
	return pool.addTxs(txs, false)
}

// addTx enqueues a single transaction into the pool if it is valid.
func (pool *TxPool) addTx(tx *types.Transaction, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Try to inject the transaction and update any state
	replace, err := pool.add(tx, local)
	if err != nil {
		return err
	}
	// If we added a new transaction, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, tx) // already validated
		pool.promoteExecutables([]common.Address{from})
	}
	return nil
}

// addTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) addTxs(txs []*types.Transaction, local bool) []error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.addTxsLocked(txs, local)
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) addTxsLocked(txs []*types.Transaction, local bool) []error {
	// Add the batch of transaction, tracking the accepted ones
	dirty := make(map[common.Address]struct{})
	errs := make([]error, len(txs))

	for i, tx := range txs {
		var replace bool
		if replace, errs[i] = pool.add(tx, local); errs[i] == nil {
			if !replace {
				from, _ := types.Sender(pool.signer, tx) // already validated
				dirty[from] = struct{}{}
			}
		}
	}
	// Only reprocess the internal state if something was actually added
	if len(dirty) > 0 {
		addrs := make([]common.Address, 0, len(dirty))
		for addr := range dirty {
			addrs = append(addrs, addr)
		}
		pool.promoteExecutables(addrs)
	}
	return errs
}

// Status returns the status (unknown/pending/queued) of a batch of transactions
// identified by their hashes.
func (pool *TxPool) Status(hashes []common.Hash) []TxStatus {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	status := make([]TxStatus, len(hashes))
	for i, hash := range hashes {
		if tx := pool.all[hash]; tx != nil {
			from, _ := types.Sender(pool.signer, tx) // already validated
			if pool.pending[from] != nil && pool.pending[from].txs.items[tx.Nonce()] != nil {
				status[i] = TxStatusPending
			} else {
				status[i] = TxStatusQueued
			}
		}
	}
	return status
}

// Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) Get(hash common.Hash) *types.Transaction {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.all[hash]
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *TxPool) removeTx(hash common.Hash) {
	// Fetch the transaction we wish to delete
	tx, ok := pool.all[hash]
	if !ok {
		return
	}
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion

	// Remove it from the list of known transactions
	delete(pool.all, hash)
	pool.priced.Removed()

	// Remove the transaction from the pending lists and reset the account nonce
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(tx); removed {
			// If no more transactions are left, remove the list
			if pending.Empty() {
				delete(pool.pending, addr)
				delete(pool.beats, addr)
			} else {
				// Otherwise postpone any invalidated transactions
				for _, tx := range invalids {
					pool.enqueueTx(tx.Hash(), tx)
				}
			}
			// Update the account nonce if needed
			if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}
			return
		}
	}
	// Transaction is in the future queue
	if future := pool.queue[addr]; future != nil {
		future.Remove(tx)
		if future.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *TxPool) promoteExecutables(accounts []common.Address) {
	// Gather all the accounts potentially needing updates
	if accounts == nil {
		accounts = make([]common.Address, 0, len(pool.queue))
		for addr := range pool.queue {
			accounts = append(accounts, addr)
		}
	}
	// Iterate over all accounts and promote any executable transactions
	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue // Just in case someone calls with a non existing account
		}
		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(pool.currentState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Removed old queued transaction", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of gas)
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable queued transaction", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
			queuedNofundsCounter.Inc(1)
		}
		// Gather all executable transactions and promote them
		for _, tx := range list.Ready(pool.pendingState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Promoting queued transaction", "hash", hash)
			pool.promoteTx(addr, hash, tx)
		}
		// Drop all transactions over the allowed limit
		if !pool.locals.contains(addr) {
			for _, tx := range list.Cap(int(pool.config.AccountQueue)) {
				hash := tx.Hash()
				delete(pool.all, hash)
				pool.priced.Removed()
				queuedRateLimitCounter.Inc(1)
				log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.queue, addr)
		}
	}
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending > pool.config.GlobalSlots {
		pendingBeforeCap := pending
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			if !pool.locals.contains(addr) && uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, float32(list.Len()))
			}
		}
		// Gradually drop transactions from offenders
		offenders := []common.Address{}
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						for _, tx := range list.Cap(list.Len() - 1) {
							// Drop the transaction from the global pools too
							hash := tx.Hash()
							delete(pool.all, hash)
							pool.priced.Removed()

							// Update the account nonce to the dropped transaction
							if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
								pool.pendingState.SetNonce(offenders[i], nonce)
							}
							log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
						}
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, tx := range list.Cap(list.Len() - 1) {
						// Drop the transaction from the global pools too
						hash := tx.Hash()
						delete(pool.all, hash)
						pool.priced.Removed()

						// Update the account nonce to the dropped transaction
						if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
							pool.pendingState.SetNonce(addr, nonce)
						}
						log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
					}
					pending--
				}
			}
		}
		pendingRateLimitCounter.Inc(int64(pendingBeforeCap - pending))
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addresssByHeartbeat, 0, len(pool.queue))
		for addr := range pool.queue {
			if !pool.locals.contains(addr) { // don't drop locals
				addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
			}
		}
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			if size := uint64(list.Len()); size <= drop {
				for _, tx := range list.Flatten() {
					pool.removeTx(tx.Hash())
				}
				drop -= size
				queuedRateLimitCounter.Inc(int64(size))
				continue
			}
			// Otherwise drop only last few transactions
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeTx(txs[i].Hash())
				drop--
				queuedRateLimitCounter.Inc(1)
			}
		}
	}
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr)

		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(nonce) {
			hash := tx.Hash()
			log.Trace("Removed old pending transaction", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
			pendingNofundsCounter.Inc(1)
		}
		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)
			pool.enqueueTx(hash, tx)
		}
		// If there's a gap in front, warn (should never happen) and postpone all transactions
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			for _, tx := range list.Cap(0) {
				hash := tx.Hash()
				log.Error("Demoting invalidated transaction", "hash", hash)
				pool.enqueueTx(hash, tx)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.pending, addr)
			delete(pool.beats, addr)
		}
	}
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addresssByHeartbeat []addressByHeartbeat

func (a addresssByHeartbeat) Len() int           { return len(a) }
func (a addresssByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addresssByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// accountSet is simply a set of addresses to check for existence, and a signer
// capable of deriving addresses from transactions.
type accountSet struct {
	accounts map[common.Address]struct{}
	signer   types.Signer
}

// newAccountSet creates a new address set with an associated signer for sender
// derivations.
func newAccountSet(signer types.Signer) *accountSet {
	return &accountSet{
		accounts: make(map[common.Address]struct{}),
		signer:   signer,
	}
}

// contains checks if a given address is contained within the set.
func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist
}

// containsTx checks if the sender of a given tx is within the set. If the sender
// cannot be derived, this method returns false.
func (as *accountSet) containsTx(tx *types.Transaction) bool {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		return as.contains(addr)
	}
	return false
}

// add inserts a new address into the set to track.
func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{}
}

func ReplayToCommitteeOnce(sender common.Address, to common.Address, gasPrice *big.Int, pool *TxPool, data []byte, store *keystore.KeyStore) {
	fmt.Println("--------------ReplayToCommitteeOnce-----------------")
	copy(data[:len(DefaultSendTagMsg)], []byte(DefaultReplayMsg)[:])
	tx := GenerateTransaction(sender, to, big.NewInt(0), pool, gasPrice, data)
	fmt.Printf("after generateTransaction .the tx.To() is %x \n", tx.To())
	senderNow, _ := types.Sender(pool.signer, tx)
	fmt.Printf("after generateTransaction .the tx.Sender is %x \n", senderNow)
	accounts := store.Accounts()
	fmt.Printf("accounts::::::::::: %#v\n", accounts)
	fmt.Println("accounts num is ::::", len(accounts))
	signTx, err := store.SignTx(accounts[0], tx, pool.chainconfig.ChainId)
	if err != nil {
		log.Info("Transaction pool committee internal communication callback error, error content is ", err)
	}
	fmt.Println("ReplayToCommittee ::: fineshed SignTx")
	//bool, err := pool.enqueueTx(txHash, signTx)
	// Add the batch of transaction, tracking the accepted ones
	//dirty := make(map[common.Address]struct{})
	replace, err := pool.add(signTx, true)
	fmt.Println("finished pool.add in go func replace and err is ", replace, err)
	if err != nil {
		return
	}
	fmt.Println("------ TxPool finished pool.add ------")
	// If we added a new transaction, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, signTx) // already validated
		fmt.Printf("---- go func prepare to go into promoteExecutables and from is ::: %x\n", from)
		pool.promoteExecutables([]common.Address{from})
	}
}

func ReplayToCommittee(sender common.Address, to common.Address, gasPrice *big.Int, pool *TxPool, data []byte, store *keystore.KeyStore, msg []byte) {
	fmt.Println("--------------ReplayToCommittee-----------------")
	tx := GenerateTransaction(sender, to, big.NewInt(0), pool, gasPrice, data)
	fmt.Printf("after generateTransaction .the tx is %#x \n", tx)
	accounts := store.Accounts()
	fmt.Printf("accounts::::::::::: %#v\n", accounts)
	fmt.Println("accounts num is ::::", len(accounts))
	signTx, err := store.SignTx(accounts[0], tx, pool.chainconfig.ChainId)
	if err != nil {
		log.Info("Transaction pool committee internal communication callback error, error content is ", err)
	}
	fmt.Println("ReplayToCommittee ::: fineshed SignTx")
	//bool, err := pool.enqueueTx(txHash, signTx)
	// Add the batch of transaction, tracking the accepted ones
	//dirty := make(map[common.Address]struct{})
	replace, err := pool.add(signTx, true)
	fmt.Println("finished pool.add in go func replace and err is ", replace, err)
	if err != nil {
		return
	}
	fmt.Println("------ TxPool finished pool.add ------")
	// If we added a new transaction, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, signTx) // already validated
		fmt.Printf("---- go func prepare to go into promoteExecutables and from is ::: %x\n", from)
		pool.promoteExecutables([]common.Address{from})
	}
	GlobalMsgMapStore(sender, msg, signTx.Hash())
	if err == nil {
		select {
		case <-time.After(20 * time.Second):
			go ReplayToCommittee(sender, to, gasPrice, pool, data, store, msg)
			return
		case <-replayCh:
			//if GlobalMsgMapLoad(txHash) {
			return
			//} else {
			//	ReplayToCommittee(sender, to, gasPrice, pool, data, store, msg)
			//	return
			//}
		}
	}
}

func GenerateTransaction(from common.Address, to common.Address, value *big.Int, pool *TxPool, gasPrice *big.Int, data []byte) *types.Transaction {
	fmt.Println("----------------GenerateTransaction----------------")
	managedState := pool.State()
	nonce := managedState.GetNonce(from) + 1
	managedState.SetNonce(from, nonce)
	//newData := data
	gasLimit := big.NewInt(defaultGasForCommittee).Uint64()
	fmt.Println("---- before NewTransaction ----", nonce, to, value, gasLimit, gasLimit, data)
	return types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
}

var GlobalMsgStoreMap sync.Map

var GlobalMsgKeyStoreSlice []common.Hash

type Interior struct {
	Info map[common.Hash][]msgInfo
}

type msgInfo struct {
	addr  common.Address
	nonce uint64
	msg   []byte
}

type Persistence struct {
	Sender common.Address `json:"sender"`
	Nonce  uint64         `json:"nonce"`
	Msg    []byte         `json:"msg"`
}

func NewInterior() *Interior {
	return &Interior{
		Info: make(map[common.Hash][]msgInfo),
	}
}

func (i *Interior) SetInfoIntoMap(sender common.Address, msg []byte, nonce uint64, txHash common.Hash) {
	value := msgInfo{
		nonce: nonce,
		msg:   msg,
		addr:  sender}
	i.insert(txHash, value)
}

func (i *Interior) insert(txHash common.Hash, msg msgInfo) {
	i.Info[txHash] = append(i.Info[txHash], msg)
}

func (i *Interior) DeleteByKey(txHash common.Hash) error {
	if _, ok := i.Info[txHash]; !ok {
		return errors.New("given address is not exist in the map")
	}
	delete(i.Info, txHash)
	return nil
}

func (i *Interior) GetTheWholeMap() map[common.Hash][]msgInfo {
	return i.Info
}

func (i *Interior) FindIfExist(txHash common.Hash) (x bool) {
	_, x = i.Info[txHash]
	return
}

func NewPersistence(sender common.Address, nonce uint64, msg []byte) *Persistence {
	return &Persistence{
		Sender: sender,
		Nonce:  nonce,
		Msg:    msg,
	}
}

func (n *Persistence) PutIntoDatabase() error {
	db, err := db.OpenFile("", nil)
	if err != nil {
		return err
	}
	uniqueKey := getUniqueKey(n.Sender, n.Nonce)
	uniqueValue := n.Msg
	err = db.Put(uniqueKey, uniqueValue, nil)
	if err != nil {
		return err
	}
	return nil
}

func (n *Persistence) GetFromDatabase(sender common.Address, nonce uint64) ([]byte, error) {
	uniqueKey := getUniqueKey(sender, nonce)
	db, err := db.OpenFile("", nil)
	if err != nil {
		return nil, err
	}
	msg, err := db.Get(uniqueKey, nil)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func getUniqueKey(sender common.Address, nonce uint64) []byte {
	nonceToByte := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceToByte, nonce)

	unique := make([]byte, len(sender)+len(nonceToByte))

	copy(unique[:len(sender)], sender[:])
	copy(unique[len(sender):], nonceToByte)

	return unique
}

func AnalyticMsgInfo(cryptoMsg []byte, localAccount accounts.Account, store *keystore.KeyStore) ([]byte, error) {
	fmt.Println("-------- AnlyticMsgInfo ---------")
	//Key, err := store.GetStorage().GetKey(localAccount.Address, localAccount.URL.Path, "")
	//if err != nil {
	//	return nil, err
	//}
	//privateKeyECDSA := Key.PrivateKey
	//privateKeyEcies := ecies.ImportECDSA(privateKeyECDSA)
	privateKeyEcies := ecies.ImportECDSA(privateKeyECDSA_text)
	msg, err := privateKeyEcies.Decrypt(rand.Reader, cryptoMsg, nil, nil)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func GlobalMsgMapStore(sender common.Address, msg []byte, txHash common.Hash) {
	fmt.Println("--------------- GlobalMsgMapStore ---------------")
	GlobalMsgKeyStoreSlice = append(GlobalMsgKeyStoreSlice, txHash)
	msgStoreKey := txHash
	msgStoreValue := make([]byte, len(sender)+len(msg))
	copy(msgStoreValue[:len(sender)], sender[:])
	copy(msgStoreValue[len(sender):], msg)
	GlobalMsgStoreMap.Store(msgStoreKey, msgStoreValue)
	fmt.Println("------------- check the global map ------------")
	fmt.Printf("%x\n", string(GetValueByKey(msgStoreKey)[:]))
}

func GlobalMsgMapLoad(key interface{}) bool {
	fmt.Println("--------------- GlobalMsgMapLoad ----------------")
	_, exist := GlobalMsgStoreMap.Load(key)
	return exist
}

func GlobalMsgMapDelete(key interface{}) {
	fmt.Println("------------ GlobalMsgMapDelete -------------")
	GlobalMsgStoreMap.Delete(key)
	for i, index := range GlobalMsgKeyStoreSlice {
		if reflect.DeepEqual(key, index) {
			GlobalMsgKeyStoreSlice = append(GlobalMsgKeyStoreSlice[:i], GlobalMsgKeyStoreSlice[i+1:]...)
		}
	}
}

// 查询全局Map ， 无任何参数，每次调用返回当前最新的一条已获取的Msg明文信息
func GetTheLastInternalTrans() (common.Address, []byte) {
	if len(GlobalMsgKeyStoreSlice) == 0 {
		return common.Address{}, nil
	}

	maxIndex := len(GlobalMsgKeyStoreSlice) - 1
	lastKeyInMap := GlobalMsgKeyStoreSlice[maxIndex]
	info := GetValueByKey(lastKeyInMap)
	if info != nil {
		senderAddr := common.Address{}
		copy(senderAddr[:], info[:len(common.Address{})])
		//senderAddr[:] = info[:len(common.Address{})]
		msgInfo := info[len(common.Address{}):]
		GlobalMsgMapDelete(lastKeyInMap)
		return senderAddr, msgInfo
	}
	GlobalMsgMapDelete(lastKeyInMap)
	return common.Address{}, nil
}

func GetValueByKey(key interface{}) []byte {
	value, ok := GlobalMsgStoreMap.Load(key)
	if ok {
		msgInfo, valid := value.([]byte)
		if valid {
			return msgInfo
		} else {
			return nil
		}
	}
	return nil
}