package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/eth"
	lpTypes "github.com/livepeer/go-livepeer/eth/types"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

var AuthType_LPE = "Livepeer-Eth-1"

type orchestrator struct {
	transcoder string
	address    ethcommon.Address
	node       *core.LivepeerNode
}

type Orchestrator interface {
	Transcoder() string
	Address() ethcommon.Address
	Sign(string) ([]byte, error)
	GetJob(int64) (*lpTypes.Job, error)
}

// Orchestator interface methods
func (orch *orchestrator) Transcoder() string {
	return orch.transcoder
}

func (orch *orchestrator) GetJob(jid int64) (*lpTypes.Job, error) {
	if orch.node == nil || orch.node.Eth == nil {
		return nil, fmt.Errorf("Cannot get job; missing eth client")
	}
	return orch.node.Eth.GetJob(big.NewInt(jid))
}

func (orch *orchestrator) Sign(msg string) ([]byte, error) {
	if orch.node == nil || orch.node.Eth == nil {
		return []byte{}, fmt.Errorf("Cannot sign; missing eth client")
	}
	return orch.node.Eth.Sign(crypto.Keccak256([]byte(msg)))
}

func (orch *orchestrator) Address() ethcommon.Address {
	return orch.address
}

// grpc methods
func (o *orchestrator) GetTranscoder(context context.Context, req *TranscoderRequest) (*TranscoderReply, error) {
	return GetTranscoder(context, o, req)
}

type broadcaster struct {
	node *core.LivepeerNode
}
type Broadcaster interface {
	Sign(string) ([]byte, error)
}

func (bcast *broadcaster) Sign(msg string) ([]byte, error) {
	if bcast.node == nil || bcast.node.Eth == nil {
		return []byte{}, fmt.Errorf("Cannot sign; missing eth client")
	}
	return bcast.node.Eth.Sign(crypto.Keccak256([]byte(msg)))
}

func genTranscoderReq(b Broadcaster, jid int64) (*TranscoderRequest, error) {
	sig, err := b.Sign(fmt.Sprintf("%v", jid))
	if err != nil {
		return nil, err
	}
	return &TranscoderRequest{JobId: jid, Sig: sig}, nil
}

func verifyMsgSig(addr ethcommon.Address, msg string, sig []byte) bool {
	return eth.VerifySig(addr, crypto.Keccak256([]byte(msg)), sig)
}

func verifyTranscoderReq(orch Orchestrator, req *TranscoderRequest, job *lpTypes.Job) bool {
	if !verifyMsgSig(job.BroadcasterAddress, fmt.Sprintf("%v", job.JobId), req.Sig) {
		glog.Error("Transcoder req sig check failed")
		return false
	}
	return true
}

func genCreds(orch Orchestrator, job *lpTypes.Job) (string, error) {
	// TODO add issuance and expiry
	sig, err := orch.Sign(fmt.Sprintf("%v", job.JobId))
	if err != nil {
		return "", err
	}
	data, err := proto.Marshal(&AuthToken{JobId: job.JobId.Int64(), Sig: sig})
	if err != nil {
		glog.Error("Unable to marshal ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func verifyCreds(orch Orchestrator, creds string) (*AuthToken, bool) {
	buf, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		glog.Error("Unable to base64-decode ", err)
		return nil, false
	}
	var token AuthToken
	err = proto.Unmarshal(buf, &token)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return nil, false
	}
	if !verifyMsgSig(orch.Address(), fmt.Sprintf("%v", token.JobId), token.Sig) {
		glog.Error("Sig check failed")
		return nil, false
	}
	return &token, true
}

func genSegCreds(bcast Broadcaster, streamId string, segData *SegData) (string, error) {
	seg := &lpTypes.Segment{
		StreamID:              streamId,
		SegmentSequenceNumber: big.NewInt(segData.Seq),
		DataHash:              ethcommon.BytesToHash(segData.Hash),
	}
	sig, err := bcast.Sign(string(seg.Flatten()))
	if err != nil {
		return "", nil
	}
	segData.Sig = sig
	data, err := proto.Marshal(segData)
	if err != nil {
		glog.Error("Unable to marshal ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func verifySegCreds(job *lpTypes.Job, segCreds string) bool {
	buf, err := base64.StdEncoding.DecodeString(segCreds)
	if err != nil {
		glog.Error("Unable to base64-decode ", err)
		return false
	}
	var segData SegData
	err = proto.Unmarshal(buf, &segData)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return false
	}
	seg := &lpTypes.Segment{
		StreamID:              job.StreamId,
		SegmentSequenceNumber: big.NewInt(segData.Seq),
		DataHash:              ethcommon.BytesToHash(segData.Hash),
	}
	if !verifyMsgSig(job.BroadcasterAddress, string(seg.Flatten()), segData.Sig) {
		glog.Error("Sig check failed")
		return false
	}
	return true
}

func GetTranscoder(context context.Context, orch Orchestrator, req *TranscoderRequest) (*TranscoderReply, error) {
	job, err := orch.GetJob(req.JobId)
	if err != nil {
		glog.Error("Unable to get job ", err)
		return nil, err
	}
	if !verifyTranscoderReq(orch, req, job) {
		return nil, fmt.Errorf("Invalid transcoder request")
	}
	creds, err := genCreds(orch, job)
	if err != nil {
		return nil, err
	}
	tr := TranscoderReply{
		Transcoder:  orch.Transcoder(),
		Credentials: creds,
		ManifestUri: orch.Transcoder() + "/stream/" + job.StreamId + ".m3u8",
	}
	return &tr, nil
}

func (orch *orchestrator) ServeSegment(w http.ResponseWriter, r *http.Request) {
	authType := r.Header.Get("Authorization")
	creds := r.Header.Get("Credentials")
	if AuthType_LPE != authType {
		glog.Error("Invalid auth type ", authType)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token, ok := verifyCreds(orch, creds)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	job, err := orch.GetJob(token.JobId)
	if err != nil || job == nil {
		glog.Error("Could not get job ", err)
		http.Error(w, "Not Found", http.StatusNotFound)
	}

	// check the segment sig from the broadcaster
	seg := r.Header.Get("Livepeer-Segment")
	verifySegCreds(job, seg)

	w.Write([]byte("The segment has been successfully transcoded."))
}

type lphttp struct {
	orchestrator *grpc.Server
	transcoder   *http.ServeMux
}

func (h *lphttp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if r.ProtoMajor == 2 && strings.HasPrefix(ct, "application/grpc") {
		h.orchestrator.ServeHTTP(w, r)
	} else {
		h.transcoder.ServeHTTP(w, r)
	}
}

func StartTranscodeServer(bind string, node *core.LivepeerNode) {
	s := grpc.NewServer()
	addr := node.Eth.Account().Address
	orch := orchestrator{transcoder: bind, node: node, address: addr}
	RegisterOrchestratorServer(s, &orch)
	lp := lphttp{
		orchestrator: s,
		transcoder:   http.NewServeMux(),
	}
	lp.transcoder.HandleFunc("/segment", orch.ServeSegment)
	cert, key, err := getCert(addr.Hex()+".transcoder.eth", node.WorkDir)
	if err != nil {
		return // XXX return error
	}
	http.ListenAndServeTLS(bind, cert, key, &lp)
}

func StartBroadcastClient(orchestratorServer string, node *core.LivepeerNode) (*http.Client, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	conn, err := grpc.Dial(orchestratorServer,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
		return nil, err
	}
	defer conn.Close()
	c := NewOrchestratorClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b := broadcaster{node: node}
	req, err := genTranscoderReq(&b, 1234)
	r, err := c.GetTranscoder(ctx, req)
	if err != nil {
		log.Fatalf("Could not get transcoder: %v", err)
		return nil, err
	}
	resp, err := httpc.Get(r.Transcoder + "/segment")
	if err != nil {
		log.Fatalf("Could not get segment response: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	log.Println(string(data))
	return httpc, nil
}

}
