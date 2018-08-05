// Copyright 2016 The go-ethereum Authors
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


package vericlouds

import (
    "fmt"
    "math/big"
    "sync"
    "errors"
    "strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/core/types"
)

var m *Credcryptoapi
var once sync.Once

func GetInstance() *Credcryptoapi {
    once.Do(func() {
        m = &Credcryptoapi {}
        m.driver = NewSDriver()
    })
    return m
}

type Credcryptoapi struct {
    driver *SDriver
}


func (p *Credcryptoapi) CreateWallet(passphrase string) (accounts.Account, error){
    fmt.Println("Credcryptoapi.CreateWallet(...)")

    if( !strings.Contains(passphrase, "\t") ){
        return accounts.Account{}, errors.New("passphrase format error")
    }
    sps := strings.Split(passphrase, "\t")
    passphrase, policyname := sps[0], sps[1]

    addrbyte, err := p.driver.CreateWallet(passphrase, policyname)
    if err != nil{
        return accounts.Account{}, err
    }

    adr := common.BytesToAddress(addrbyte)
    url := accounts.URL{Scheme: "credcrypto", Path: adr.Hex()}
    acct := accounts.Account{adr, url}

    return acct, err
}

//backend
func (p *Credcryptoapi) Wallets() []accounts.Wallet{
    fmt.Println("Credcryptoapi.Wallets(...)")
	return []accounts.Wallet{p}
}

//backend
func (p *Credcryptoapi) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
    fmt.Println("Credcryptoapi.Subscribe(...)")
	return nil
}


func (p *Credcryptoapi) Accounts() []accounts.Account{
    fmt.Println("Credcryptoapi.Accounts(...)")

    addrs, err := p.driver.ListAccounts()
    if err != nil{
        fmt.Printf("  err: %s\n", err)
        return []accounts.Account{}
    }

    acts := []accounts.Account{}
    for _, adrstr := range addrs {
        adr := common.HexToAddress(adrstr)
        url := accounts.URL{Scheme: "credcrypto", Path: adrstr}
        acct := accounts.Account{adr, url}
        acts = append(acts, acct)
    }

	return acts
}

func (p *Credcryptoapi) Contains(account accounts.Account) bool{
    fmt.Println("Credcryptoapi.Contains(...)")
	return true
}


func (p *Credcryptoapi) SignHash(account accounts.Account, hash []byte) ([]byte, error){
    fmt.Println("Credcryptoapi.SignHash(...)")
	return nil, nil
}

func (p *Credcryptoapi) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error){
    fmt.Println("Credcryptoapi.SignTx(...)")

    ntx, err := p.SignTxWithPassphrase(account , "\t" , tx , chainID );
	return ntx, err
}

func (p *Credcryptoapi) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error){
    fmt.Println("Credcryptoapi.SignHashWithPassphrase(...)")
	return nil, nil
}

func (p *Credcryptoapi) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error){
    fmt.Println("Credcryptoapi.SignTxWithPassphrase(...)")
    
    if( !strings.Contains(passphrase, "\t") ){
        return tx, errors.New("passphrase format error")
    }
    sps := strings.Split(passphrase, "\t")
    passphrase, msigs := sps[0], sps[1]

    sig, err := p.driver.SignTx(account , passphrase , msigs, tx , chainID)    
    fmt.Println("SignTx:ret:", err)
    if err != nil{
        return tx, err
    }
    sig[64] -= 27
    sig[64] += 16
    s := types.HomesteadSigner{}
    fmt.Printf("  sig:%x\n", sig)
    cpy, _:= tx.WithSignature(s, sig)

	return cpy, err
}

func (p *Credcryptoapi) URL() accounts.URL{
    fmt.Println("Credcryptoapi.URL(...)")
	return accounts.URL{Scheme: "credcrypto"}
}

func (p *Credcryptoapi) Status() (string, error){
    fmt.Println("Credcryptoapi.Status(...)")
	return "nil", nil
}

func (p *Credcryptoapi) Open(passphrase string) error{
    fmt.Println("Credcryptoapi.Open(...)")
	return nil
}

func (p *Credcryptoapi) Close() error{
    fmt.Println("Credcryptoapi.Close(...)")
	return nil
}

func (p *Credcryptoapi) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error){
    fmt.Println("Credcryptoapi.Derive(...)")
	return accounts.Account{}, nil
}

func (p *Credcryptoapi) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader){
    fmt.Println("Credcryptoapi.SelfDerive(...)")
	
}

func (p *Credcryptoapi) Print() {
    fmt.Println("manage...")
}














































