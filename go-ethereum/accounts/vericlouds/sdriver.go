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
    "syscall"
    "math/big"
    //"unsafe"
    "strings"
    "path"
    "os"
    "C"
    "encoding/hex"
    "io/ioutil"
    "path/filepath"
    "strconv"
    //"net"
    "bytes"
    "errors"
    "net/http"
    //sysjson "encoding/json"
    //"net/rpc/jsonrpc"
    //"runtime"
    //"strconv"
    //"reflect"

    "github.com/ethereum/go-ethereum/rlp"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/accounts"

    "github.com/gorilla/rpc/json"
)


type SDriver struct {
    dll *syscall.DLL

    chainid uint

    exportedf_seal_and_save *syscall.Proc
    exportedf_sign_transaction *syscall.Proc
}

func NewSDriver() *SDriver{
    driver := &SDriver{}
    driver.init()
    return driver
}


func (p *SDriver) init() (error){
    fmt.Println("SDriver.init(...)")




    ex, err := os.Executable()
    if err != nil {
        panic(err)
    }
    cPath :=  path.Join(filepath.Dir(ex), "chainid.txt")
    fmt.Println(cPath)

    b, err := ioutil.ReadFile(cPath) // just pass the file name
    if err != nil {
        panic(err)
    }
    chainidstr := strings.TrimSpace(string(b))
    fmt.Println(chainidstr)

    chainid, err := strconv.Atoi(chainidstr)
    if err != nil {
        panic(err)
    }
    p.chainid = uint(chainid)
    //errors.New("passphrase format error")

    return nil
}


func (p *SDriver) InstallWallet(prvkstr string, plcystr string) ([]byte, error){
    fmt.Println("SDriver.InstallWallet(...)")



    args:=&[]string{"1", prvkstr, plcystr}
    res, err := rpccall("import_wallet", args)
    if err != nil {
        fmt.Println(err)
        return []byte{}, err
    }
    fmt.Println(res)

    addr, err := hex.DecodeString(res)
    if err != nil {
        panic(err)
    }

    return addr, nil
}


func (p *SDriver) CreateWallet(passphrase string, plcyname string) ([]byte, error){

    fmt.Println("SDriver.CreateWallet(...)")

    args:=&[]string{"1", passphrase, plcyname}
    res, err := rpccall("create_wallet", args)
    if err != nil {
        fmt.Println(err)
        return []byte{}, err
    }
    fmt.Println(res)

    addr, err := hex.DecodeString(res)
    if err != nil {
        panic(err)
    }

    return addr, nil
}


func (p *SDriver) SignTx(account accounts.Account, passphrase string, multisigs string, tx *types.Transaction, chainID *big.Int) ([]byte, error){

    encodedtx, _ := rlp.EncodeToBytes([]interface{}{
        tx.Nonce(),
        tx.GasPrice(),
        tx.Gas(),
        tx.To(),
        tx.Value(),
        tx.Data(),
        p.chainid, uint(0), uint(0),
    })

    addr := strings.ToLower(account.Address.Hex()[2:])
    hextx := fmt.Sprintf("%x", encodedtx)


    args :=&[]string{addr, passphrase, hextx, multisigs}
    res, err := rpccall("sign_transaction", args)
    if err != nil {
        fmt.Println(err)
        return []byte{}, err
    }
    fmt.Println(res)
    fmt.Printf("  res: %s\n", res)

    data, err := hex.DecodeString(res)
    if err != nil {
        fmt.Println(err)
        return []byte{}, err
    }

    return data, nil
}


func (p *SDriver) ListAccounts() ([]string, error){

    args :=&[]string{}
    res, err := rpccall("list_wallet_addresses", args)
    if err != nil {
        fmt.Println(err)
        return []string{}, err
    }

    fmt.Printf("  res: %s\n", res)

    return strings.Split(res, ","), nil
}



func rpccall(mtd string, args interface{}) (string, error) {

    url := "http://localhost:6663/"

    message, err := json.EncodeClientRequest(mtd, args)
    if err != nil {
        fmt.Println("%s", err)
        return "", err
    }

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(message))
    if err != nil {
        fmt.Println("%s", err)
        return "", err
    }

    req.Header.Set("Content-Type", "application/json")
    client := new(http.Client)
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error in sending request to %s. %s", url, err)
        return "", err
    }
    defer resp.Body.Close()

    var result string
    err = json.DecodeClientResponse(resp.Body, &result)
    if err != nil {
        fmt.Println("Couldn't decode response. %s", err)
        return "", err
    }
    fmt.Println(result)

    
    if(strings.Count(result, "|")!=1){
        return "", errors.New(fmt.Sprintf("Couldn't decode response. %s", result))
    }

    s := strings.Split(result, "|")

    if s[0] != "0" {

        if s[0] == "8000" {
            return "", errors.New("incorrect passphrase")
        }

        return "", errors.New(fmt.Sprintf("sgx error %s", s[0]))
    }
    return s[1], nil
}

































