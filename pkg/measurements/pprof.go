// Copyright 2020 The Kube-burner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package measurements

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cloud-bulldozer/go-commons/v2/indexers"
	"github.com/kube-burner/kube-burner/v2/pkg/config"
	"github.com/kube-burner/kube-burner/v2/pkg/measurements/types"
	"github.com/kube-burner/kube-burner/v2/pkg/util/fileutils"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	"k8s.io/apimachinery/pkg/labels"
)

type pprof struct {
	BaseMeasurement

	stopChannel       chan bool
	daemonSetDeployed bool
}

type pprofLatencyMeasurementFactory struct {
	BaseMeasurementFactory
}

func newPprofLatencyMeasurementFactory(configSpec config.Spec, measurement types.Measurement, metadata map[string]any) (MeasurementFactory, error) {
	for _, target := range measurement.PProfTargets {
		if target.BearerToken != "" && (target.CertFile != "" || target.Cert != "") {
			return nil, fmt.Errorf("bearerToken and cert auth methods cannot be specified together in the same target")
		}
	}

	return pprofLatencyMeasurementFactory{
		BaseMeasurementFactory: NewBaseMeasurementFactory(configSpec, measurement, metadata),
	}, nil
}

func (plmf pprofLatencyMeasurementFactory) NewMeasurement(jobConfig *config.Job, clientSet kubernetes.Interface, restConfig *rest.Config, embedCfg *fileutils.EmbedConfiguration) Measurement {
	return &pprof{
		BaseMeasurement: plmf.NewBaseLatency(jobConfig, clientSet, restConfig, "", "", embedCfg),
	}
}

func (p *pprof) Start(measurementWg *sync.WaitGroup) error {
	defer measurementWg.Done()
	var wg sync.WaitGroup
	err := os.MkdirAll(p.Config.PProfDirectory, 0744)
	if err != nil {
		log.Fatalf("Error creating pprof directory: %s", err)
	}
	if p.needsDaemonSet() {
		if err := p.deployDaemonSet(); err != nil {
			log.Errorf("Error deploying DaemonSet: %s", err)
			return err
		}
		p.daemonSetDeployed = true
		if err := p.waitForDaemonSetReady(); err != nil {
			log.Errorf("Error waiting for DaemonSet to be ready: %s", err)
			return err
		}
	}
	p.stopChannel = make(chan bool)
	p.getPProf(&wg, true)
	wg.Wait()
	go func() {
		defer close(p.stopChannel)
		ticker := time.NewTicker(p.Config.PProfInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Copy certificates only in the first iteration
				p.getPProf(&wg, false)
				wg.Wait()
			case <-p.stopChannel:
				ticker.Stop()
				return
			}
		}
	}()
	return nil
}

func (p *pprof) getPods(target types.PProftarget, pprofNodeTarget map[string]string, isNodeTarget bool) []corev1.Pod {
	// When DaemonSet is deployed, always use DaemonSet pods for collection
	// The DaemonSet pods have curl installed and can reach node-level endpoints
	if isNodeTarget {
		labelSelector := labels.Set(pprofNodeTarget).String()
		podList, err := p.ClientSet.CoreV1().Pods(types.PprofNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: labelSelector,
			FieldSelector: "status.phase=Running",
		})
		if err != nil {
			log.Errorf("Error found listing DaemonSet pods: %s", err)
			return []corev1.Pod{}
		}
		return podList.Items
	}
	// Direct pod collection (no DaemonSet) - use labelSelector to find target pods
	labelSelector := labels.Set(target.LabelSelector).String()
	podList, err := p.ClientSet.CoreV1().Pods(target.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		log.Errorf("Error found listing pods labeled with %s: %s", labelSelector, err)
	}
	return podList.Items
}

func (p *pprof) getPProf(wg *sync.WaitGroup, first bool) {
	var err error
	for pos, target := range p.Config.PProfTargets {
		log.Infof("Collecting %s pprof", target.Name)
		pprofNodeTarget, isNodeTarget := p.getPprofNodeTargets()
		daemonSetPods := p.getPods(target, pprofNodeTarget, isNodeTarget)

		for _, daemonSetPod := range daemonSetPods {
			var cert, privKey io.Reader
			if target.CertFile != "" && target.KeyFile != "" && first {
				p.Config.PProfTargets[pos].Cert, p.Config.PProfTargets[pos].Key, err = readCerts(target.CertFile, target.KeyFile)
				if err != nil {
					log.Error(err)
					continue
				}
			}
			if target.Cert != "" && target.Key != "" && first {
				certData, err := base64.StdEncoding.DecodeString(target.Cert)
				if err != nil {
					log.Errorf("Error decoding pprof certificate data from %s", target.Name)
					continue
				}
				privKeyData, err := base64.StdEncoding.DecodeString(target.Key)
				if err != nil {
					log.Errorf("Error decoding pprof private key data from %s", target.Name)
					continue
				}
				cert = strings.NewReader(string(certData))
				privKey = strings.NewReader(string(privKeyData))
			}

			// For targets with labelSelector, find target pods on the same node and collect from each
			if p.daemonSetDeployed && len(target.LabelSelector) > 0 {
				nodeName := daemonSetPod.Spec.NodeName
				targetPods := p.getTargetPodsForNode(target, nodeName)
				if len(targetPods) == 0 {
					log.Warnf("No pods found for target %s on node %s with labelSelector %v", target.Name, nodeName, target.LabelSelector)
					continue
				}

				for _, targetPod := range targetPods {
					wg.Add(1)
					go func(target types.PProftarget, collectorPod corev1.Pod, targetPod corev1.Pod) {
						defer wg.Done()
						p.collectPProfFromPod(target, collectorPod, &targetPod, cert, privKey, first)
					}(p.Config.PProfTargets[pos], daemonSetPod, targetPod)
				}
			} else {
				// Node-level target (kubelet, crio) or direct pod collection
				wg.Add(1)
				go func(target types.PProftarget, pod corev1.Pod) {
					defer wg.Done()
					p.collectPProfFromPod(target, pod, nil, cert, privKey, first)
				}(p.Config.PProfTargets[pos], daemonSetPod)
			}
		}
	}
	wg.Wait()
}

// collectPProfFromPod handles the actual pprof collection
// collectorPod: the pod where curl is executed (DaemonSet pod or target pod itself)
// targetPod: if not nil, the pod whose pprof endpoint we're collecting (for labelSelector targets)
func (p *pprof) collectPProfFromPod(target types.PProftarget, collectorPod corev1.Pod, targetPod *corev1.Pod, cert, privKey io.Reader, first bool) {
	// Determine identifier for filename
	var identifier string
	if targetPod != nil {
		identifier = targetPod.Name
		log.Infof("Collecting pprof from target pod %s via collector pod %s on node %s", targetPod.Name, collectorPod.Name, collectorPod.Spec.NodeName)
	} else if p.daemonSetDeployed {
		identifier = collectorPod.Spec.NodeName
		log.Infof("Collecting pprof from pod %s on node %s", collectorPod.Name, collectorPod.Spec.NodeName)
	} else {
		identifier = collectorPod.Name
	}

	pprofFile := fmt.Sprintf("%s-%s-%d.pprof", target.Name, identifier, time.Now().Unix())
	f, err := os.Create(path.Join(p.Config.PProfDirectory, pprofFile))
	var stderr bytes.Buffer
	if err != nil {
		log.Errorf("Error creating pprof file %s: %s", pprofFile, err)
		return
	}
	defer f.Close()

	if cert != nil && privKey != nil && first {
		if err = p.copyCertsToPod(collectorPod, cert, privKey); err != nil {
			log.Error(err)
			return
		}
	}

	command, pprofReq := p.buildPProfRequest(target, collectorPod, targetPod)

	log.Debugf("Collecting pprof using URL: %s", pprofReq.URL())
	pprofReq.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: collectorPod.Spec.Containers[0].Name,
		Stdin:     false,
		Stderr:    true,
		Stdout:    true,
	}, scheme.ParameterCodec)
	log.Debugf("Executing %s in pod %s (namespace: %s)", command, collectorPod.Name, collectorPod.Namespace)
	exec, err := remotecommand.NewSPDYExecutor(p.RestConfig, "POST", pprofReq.URL())
	if err != nil {
		log.Errorf("Failed to execute pprof command on %s: %s", target.Name, err)
		return
	}
	err = exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: f,
		Stderr: &stderr,
	})
	if err != nil {
		log.Errorf("Failed to get pprof from %s: %s", collectorPod.Name, stderr.String())
		os.Remove(f.Name())
	} else {
		log.Infof("Successfully collected pprof data: %s", pprofFile)
	}
}

// buildPProfRequest builds the curl command and REST request for pprof collection
// collectorPod: the pod where curl is executed
// targetPod: if not nil, the pod whose pprof endpoint we're collecting (for labelSelector targets via DaemonSet)
func (p *pprof) buildPProfRequest(target types.PProftarget, collectorPod corev1.Pod, targetPod *corev1.Pod) ([]string, *rest.Request) {
	var pprofReq *rest.Request
	var command []string

	// When using DaemonSet for collection
	if p.daemonSetDeployed {
		if targetPod != nil {
			// Pod-level target (coredns, metrics-server) collected via DaemonSet
			// Use the target pod's IP to reach its pprof endpoint from the DaemonSet pod (hostNetwork)
			podIP := targetPod.Status.PodIP
			if podIP == "" {
				log.Errorf("Target pod %s has no IP address", targetPod.Name)
				return nil, nil
			}

			// Replace localhost in URL with pod IP
			url := target.URL
			url = strings.Replace(url, "localhost", podIP, 1)
			url = strings.Replace(url, "127.0.0.1", podIP, 1)

			if target.BearerToken != "" {
				command = []string{"curl", "-fsSLk", "-H", fmt.Sprintf("Authorization: Bearer %s", target.BearerToken), url}
			} else if target.Cert != "" && target.Key != "" {
				command = []string{"curl", "-fsSLk", "--cert", "/tmp/pprof.crt", "--key", "/tmp/pprof.key", url}
			} else {
				command = []string{"curl", "-fsSLk", url}
			}
		} else if strings.HasPrefix(target.URL, "unix://") {
			// Unix socket (CRI-O) - node-level
			socketPath := strings.TrimPrefix(target.URL, "unix://")

			pprofPath := "/debug/pprof/profile"
			if strings.Contains(target.Name, "heap") {
				pprofPath = "/debug/pprof/heap"
			} else if strings.Contains(target.Name, "goroutine") {
				pprofPath = "/debug/pprof/goroutine"
			}

			seconds := int(p.Config.PProfInterval.Seconds())
			if seconds > 300 {
				seconds = 30
			}

			command = []string{"curl", "-fsSLk",
				"--unix-socket", socketPath,
				fmt.Sprintf("http://localhost%s?seconds=%d", pprofPath, seconds),
			}
			log.Debugf("Using unix socket: %s for %s", socketPath, pprofPath)
		} else {
			// HTTPS/HTTP endpoint (kubelet, etc.) - node-level
			command = []string{"sh", "-c",
				fmt.Sprintf("curl -fsSLk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" %s", target.URL),
			}
		}

		pprofReq = p.ClientSet.CoreV1().
			RESTClient().
			Post().
			Resource("pods").
			Name(collectorPod.Name).
			Namespace(types.PprofNamespace).
			SubResource("exec")
	} else {
		// Direct pod-level collection (no DaemonSet) - exec into target pod
		if target.BearerToken != "" {
			command = []string{"curl", "-fsSLk", "-H", fmt.Sprintf("Authorization: Bearer %s", target.BearerToken), target.URL}
		} else if target.Cert != "" && target.Key != "" {
			command = []string{"curl", "-fsSLk", "--cert", "/tmp/pprof.crt", "--key", "/tmp/pprof.key", target.URL}
		} else {
			command = []string{"curl", "-fsSLk", target.URL}
		}
		pprofReq = p.ClientSet.CoreV1().
			RESTClient().
			Post().
			Resource("pods").
			Name(collectorPod.Name).
			Namespace(collectorPod.Namespace).
			SubResource("exec")
	}
	return command, pprofReq
}

func (p *pprof) Collect(measurementWg *sync.WaitGroup) {
	defer measurementWg.Done()
}

func (p *pprof) Stop() error {
	p.stopChannel <- true
	return nil
}

// Fake index function for pprof
func (p *pprof) Index(_ string, _ map[string]indexers.Indexer) {
}

func readCerts(cert, privKey string) (string, string, error) {
	var certFd, privKeyFd *os.File
	var certData, privKeyData []byte
	certFd, err := os.Open(cert)
	if err != nil {
		return "", "", fmt.Errorf("cannot read %s, skipping: %v", cert, err)
	}
	privKeyFd, err = os.Open(privKey)
	if err != nil {
		return "", "", fmt.Errorf("cannot read %s, skipping: %v", cert, err)
	}
	certData, err = io.ReadAll(certFd)
	if err != nil {
		return "", "", err
	}
	privKeyData, err = io.ReadAll(privKeyFd)
	if err != nil {
		return "", "", err
	}
	return string(certData), string(privKeyData), nil
}

func (p *pprof) copyCertsToPod(pod corev1.Pod, cert, privKey io.Reader) error {
	var stderr bytes.Buffer
	log.Infof("Copying certificate and private key into %s %s", pod.Name, pod.Spec.Containers[0].Name)
	fMap := map[string]io.Reader{
		"/tmp/pprof.crt": cert,
		"/tmp/pprof.key": privKey,
	}
	for dest, f := range fMap {
		req := p.ClientSet.CoreV1().
			RESTClient().
			Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("exec")
		req.VersionedParams(&corev1.PodExecOptions{
			Command:   []string{"tee", dest},
			Container: pod.Spec.Containers[0].Name,
			Stdin:     true,
			Stderr:    true,
			Stdout:    false,
		}, scheme.ParameterCodec)
		exec, err := remotecommand.NewSPDYExecutor(p.RestConfig, "POST", req.URL())
		if err != nil {
			return fmt.Errorf("failed to establish SPDYExecutor on %s: %s", pod.Name, err)
		}
		err = exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
			Stdin:  f,
			Stdout: nil,
			Stderr: &stderr,
		})
		if err != nil || stderr.String() != "" {
			return fmt.Errorf("failed to copy file to %s: %s", pod.Name, stderr.Bytes())
		}
	}
	log.Infof("Certificate and private key copied into %s %s", pod.Name, pod.Spec.Containers[0].Name)
	return nil
}

func (p *pprof) IsCompatible() bool {
	return true
}
