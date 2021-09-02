package main

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/20 下午7:07
 */
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/cncc"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/verifier"
	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
	x509 "github.com/tjfoc/gmsm/sm2"
	tls "github.com/tjfoc/gmtls"
	"io/ioutil"
	http "net/http1"
	"os"
)

var csp bccsp.BCCSP
var ver *verifier.BccspCryptoVerifier
var certBytes []byte

/**
  请求/响应数据、签名值、证书  结构体
*/
type Envelope struct {
	Data        []byte `json:"data,omitempty"`        // 请求/响应数据
	Sig         []byte `json:"sig,omitempty"`         // 签名值
	Certificate []byte `json:"certificate,omitempty"` // 证书
}

/*
  业务合约请求数据  结构体
*/
type QueryBaseInfo struct {
	ContractName string                 `json:contractName,omitempty"` // 应用合约名字
	Method       string                 `json:"method,omitempty"`      // 请求的方法
	Params       map[string]interface{} `json:"params,omitempty"`      // 请求的数据
}

var info QueryBaseInfo

func init() {
	song := make(map[string]interface{})

	song["certDn"] = "CN=CNCC"
	song["cover"] = true
	song["port"] = 34997

	info = QueryBaseInfo{ContractName: "CONTRACT01", Method: "post", Params: song}
}

func main() {

	rootPEM, err := ioutil.ReadFile("/opt/go-projects/tls-server-rest/cert/tlsca")
	if err != nil {
		fmt.Println(err.Error())
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		panic("failed to parse root certificate")
	}
	certBytes = rootPEM

	os.Setenv("CORE_PEER_BCCSP_CNCC_GM_IP", "47.95.204.66")
	os.Setenv("CORE_PEER_BCCSP_CNCC_GM_PORT", "34997")
	os.Setenv("CORE_PEER_BCCSP_CNCC_GM_PASSWORD", "1")
	opts := factory.GetDefaultOpts()

	csp, err := (&factory.CNCC_GMFactory{}).Get(opts)
	if err != nil {
		log.Errorf("获取 Bccsp 实例失败：%s", err.Error())
		panic("获取Bccsp实例失败：" + err.Error())
	}
	factory.SetBCCSP(opts.ProviderName, csp)
	ver, err = verifier.New(csp, nil)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Verifier: ver},
	}

	client := &http.Client{Transport: tr}

	bytesData, _ := json.Marshal(info)

	envelope := Envelope{
		Data:        bytesData,
		Certificate: certBytes,
	}
	// 签名
	hash, err := csp.Hash(bytesData, &bccsp.SHA256Opts{})
	if err != nil {
		log.Error(errors.WithMessagef(err, "计算哈希失败, data = %s ", base64.StdEncoding.EncodeToString(bytesData)).Error())
	}
	cert, err := x509.ReadCertificateFromMem(certBytes)
	if err != nil {
		log.Error(errors.WithMessagef(err, "解析签名证书失败, cert = %s", string(certBytes)).Error())
	}
	sig, err := ver.Sign(cert.SubjectKeyId, hash)
	if err != nil {
		log.Error(errors.WithMessagef(err, "签名失败, KeyLabel = %s, hash = %s", cncc.KeyPrefix+string(cert.SubjectKeyId), base64.StdEncoding.EncodeToString(hash)).Error())
	}
	envelope.Sig = sig
	marshalBytes, err := json.Marshal(envelope)
	// 验签
	hash, err = csp.Hash(bytesData, &bccsp.SHA256Opts{})
	if err != nil {
		log.Error(errors.WithMessagef(err, "计算哈希失败, data = %s ", base64.StdEncoding.EncodeToString(bytesData)).Error())
		return
	}
	cert, err = x509.ReadCertificateFromMem(certBytes)
	if err != nil {
		log.Error(errors.WithMessagef(err, "解析签名证书失败, cert = %s", string(certBytes)).Error())
		return
	}
	result, err := ver.Verify(cert.SubjectKeyId, sig, hash)
	if err != nil {
		log.Error(errors.WithMessagef(err, "签名失败, KeyLabel = %s, hash = %s", cncc.KeyPrefix+string(cert.SubjectKeyId), base64.StdEncoding.EncodeToString(hash)))
		return
	}
	log.Info(result)
	res, err := client.Post("https://127.0.0.1:9443/oracle/invoke",
		"application/json;charset=utf-8", bytes.NewBuffer(marshalBytes))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return
	}
	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Failed to read response body: %s", err.Error())
	}
	if res.StatusCode == 200 {
		resEnvelope := Envelope{}
		err = json.Unmarshal(content, &resEnvelope)
		if err != nil {
			log.Errorf("Failed to read response body: %s, error: %s", content, err.Error())
		}
		//resp := make(map[string]interface{})
		//err = json.Unmarshal(content, &resp)
		//if err != nil {
		//	log.Error(err.Error())
		//}

		log.Infof("%s", string(resEnvelope.Data))
	} else {
		//resp := make(map[string]interface{})
		//json.Unmarshal(content,&resp)
		log.Info((string)(content))
	}
	//if res.StatusCode!=200{
	//	log.Errorf("query data error: %v", res)
	//	return
	//}

	//defer res.Body.Close()
	//
	//content, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	fmt.Println("Fatal error ", err.Error())
	//}
	//
	//str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	//p10 := gojsonq.New().FromString(*str).Find("data")
	//fmt.Println(p10.(string))
	//content, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	log.Errorf("Failed to read response body: %s", err.Error())
	//}
	//resEnvelope := Envelope{}
	//err = json.Unmarshal(content, &resEnvelope)
	//if err != nil {
	//	log.Errorf("Failed to read response body: %s, error: %s", content, err.Error())
	//}
	////resp := make(map[string]interface{})
	////err = json.Unmarshal(content, &resp)
	////if err != nil {
	////	log.Error(err.Error())
	////}
	//
	//log.Infof("%s", string(resEnvelope.Data))
}
