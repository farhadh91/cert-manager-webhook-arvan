package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"os"
	"strings"

	cmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"

	"github.com/go-resty/resty/v2"
)

// DNSRecord a DNS record
//
//	{
//		"id": "497f6eca-6276-4993-bfeb-53cbbbba6f08",
//		"type": "a",
//		"name": "string",
//		"value": { },
//		"ttl": 120,
//		"cloud": false,
//		"upstream_https": "default",
//		"ip_filter_mode":
//		{},
//		"can_delete": true,
//		"is_protected": false,
//		"created_at": "2019-08-24T14:15:22Z",
//		"updated_at": "2019-08-24T14:15:22Z"
//	}
//
// DNSRecord is the read model. `value` is left raw on purpose: its shape
// depends on the record type, and a zone listing contains every type. An ns
// record answers with an array, so decoding it into a map fails and takes the
// whole listing down with it.
type DNSRecord struct {
	ID    string          `json:"id,omitempty"`
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
	Cloud bool            `json:"cloud"`
	TTL   int             `json:"ttl,omitempty"`
}

// Text returns the payload of a TXT record, or "" for any other shape.
func (r DNSRecord) Text() string {
	var value struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(r.Value, &value); err != nil {
		return ""
	}
	return value.Text
}

// dnsRecordRequest is the create payload, where the value shape is ours to
// pick and is always a TXT record.
type dnsRecordRequest struct {
	Type  string            `json:"type"`
	Name  string            `json:"name"`
	Value map[string]string `json:"value"`
	Cloud bool              `json:"cloud"`
	TTL   int               `json:"ttl,omitempty"`
}

type DNSRecords struct {
	Data []DNSRecord `json:"data"`
	Meta struct {
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
	} `json:"meta"`
}

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&arvanDNSProviderSolver{},
	)
}

// arvanDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type arvanDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// arvanDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type arvanDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	AuthAPIKey       string                  `json:"authApiKey"`
	AuthAPISecretRef cmeta.SecretKeySelector `json:"authApiSecretRef"`
	BaseURL          string                  `json:"baseUrl"`
	TTL              int                     `json:"ttl"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *arvanDNSProviderSolver) Name() string {
	return "arvancloud"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *arvanDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Error(err)
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration %v", cfg)

	apiSecret, err := c.validateAndGetSecret(&cfg, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("Failed to validate config: %v", err)
		return fmt.Errorf("Failed to validate config: %v", err)
	}

	// Resolved once and reused below: every extra api call widens the window
	// between the challenge starting and the record being visible.
	recordName, domain := c.resolveZone(&cfg, apiSecret, ch.ResolvedFQDN, ch.ResolvedZone)

	// Present has to tolerate being called repeatedly for the same challenge.
	// Returning early when our record is already published avoids deleting and
	// recreating it, which would leave the name briefly non-existent -- long
	// enough for a resolver to cache the NXDOMAIN.
	id, err := c.findRecordID(&cfg, apiSecret, domain, recordName, ch.Key)
	if err != nil {
		klog.Warningf("Could not list records of %s in %s: %v", recordName, domain, err)
	} else if id != "" {
		klog.Infof("TXT record %s in %s already holds this challenge key", recordName, domain)
		return nil
	}

	//{"type":"TXT","ttl":120,"name":"asds","cloud":false,"value":{"text":"asd"}}
	vals := make(map[string]string)
	vals["text"] = ch.Key
	record := dnsRecordRequest{
		Type:  "TXT",
		Name:  recordName,
		Value: vals,
		Cloud: false,
		TTL:   cfg.TTL,
	}

	client := resty.New()
	// See we are not setting content-type header, since go-resty automatically detects Content-Type for you
	resp, err := client.R().
		SetBody(record).
		SetHeader("Accept", "application/json").
		SetAuthToken(apiSecret).
		SetAuthScheme("Apikey").
		Post(
			c.urlFactory(
				&cfg,
				"/cdn/4.0/domains/{domain}/dns-records",
				"{domain}", domain,
			))

	// Request.Header is deliberately not logged: it carries the api key.
	klog.Info(resp.Request.URL, resp.Request.Body, resp.StatusCode(), string(resp.Body()))

	if err == nil {
		if resp.StatusCode() != 201 {
			err = fmt.Errorf("Error in creating dns record: %s", string(resp.Body()))
			klog.Error(err)
		}
	}
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *arvanDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Error(err)
		return err
	}
	apiSecret, err := c.validateAndGetSecret(&cfg, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("Failed to validate config: %v", err)
		return fmt.Errorf("Failed to validate config: %v", err)
	}

	recordName, domain := c.resolveZone(&cfg, apiSecret, ch.ResolvedFQDN, ch.ResolvedZone)
	id, err := c.findRecordID(&cfg, apiSecret, domain, recordName, ch.Key)
	if err != nil {
		klog.Error(err)
		return err
	}
	// Nothing to delete is a success: cert-manager also calls CleanUp for
	// challenges that were never presented, or already cleaned up.
	if id == "" {
		klog.Infof("No TXT record holding this challenge key in %s, nothing to clean up", domain)
		return nil
	}
	// See we are not setting content-type header, since go-resty automatically detects Content-Type for you

	client := resty.New()
	resp, err := client.R().
		SetAuthToken(apiSecret).
		SetAuthScheme("Apikey").
		SetHeader("Accept", "application/json").
		Delete(
			c.urlFactory(
				&cfg,
				"/cdn/4.0/domains/{domain}/dns-records/{id}",
				"{domain}", domain,
				"{id}", id,
			))

	// Request.Header is deliberately not logged: it carries the api key.
	klog.Info(resp.Request.URL, resp.Request.Body, resp.StatusCode(), string(resp.Body()))

	if err != nil {
		if resp == nil {
			err = fmt.Errorf("Api call has no resutl")
			klog.Error(err)
		} else if resp.StatusCode() != 200 {
			err = fmt.Errorf("Error in creating dns record: %s", string(resp.Body()))
			klog.Error(err)
		}
	}
	return err
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *arvanDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (arvanDNSProviderConfig, error) {
	cfg := arvanDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *arvanDNSProviderSolver) validateAndGetSecret(cfg *arvanDNSProviderConfig, namespace string) (string, error) {
	fmt.Printf("validateAndGetSecret...")
	// Check that the host is defined
	if cfg.AuthAPIKey != "" {
		return cfg.AuthAPIKey, nil
	}

	// Try to load the API key
	if cfg.AuthAPISecretRef.LocalObjectReference.Name == "" {
		return "", errors.New("No Arvan API secret provided")
	}

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.TODO(), cfg.AuthAPISecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		klog.Error(err)
		return "", err
	}

	secBytes, ok := sec.Data[cfg.AuthAPISecretRef.Key]
	if !ok {
		return "", fmt.Errorf("Key %q not found in secret \"%s/%s\"", cfg.AuthAPISecretRef.Key, cfg.AuthAPISecretRef.LocalObjectReference.Name, namespace)
	}

	apiKey := string(secBytes)

	return apiKey, nil
}

func (c *arvanDNSProviderSolver) urlFactory(cfg *arvanDNSProviderConfig, uri string, args ...string) string {
	r := strings.NewReplacer(args...)
	urlFormat := "https://napi.arvancloud.com" + uri
	if cfg.BaseURL != "" {
		urlFormat = cfg.BaseURL + uri
	}
	return r.Replace(urlFormat)
}

// resolveZone returns the record name and the zone it has to be created in.
// The zone cannot be derived from the fqdn alone: sub.example.com may be a
// record inside example.com or a delegated zone of its own, and only the
// account holding it knows which. So every possible parent is checked against
// the api, longest first, and the first one that exists wins: a delegated
// child zone is always longer than its parent.
// Falls back to the zone cert-manager resolved over DNS when the api answers
// for none of them.
func (c *arvanDNSProviderSolver) resolveZone(cfg *arvanDNSProviderConfig, apiSecret, fqdn, resolvedZone string) (record, domain string) {
	fqdn = util.UnFqdn(fqdn)
	labels := strings.Split(fqdn, ".")
	for i := 0; len(labels)-i >= 2; i++ {
		// _acme-challenge.* is the record itself, never a hosted zone.
		if strings.HasPrefix(labels[i], "_") {
			continue
		}
		candidate := strings.Join(labels[i:], ".")
		if c.zoneExists(cfg, apiSecret, candidate) {
			klog.Infof("Request : %s => %s", fqdn, candidate)
			return strings.TrimSuffix(strings.TrimSuffix(fqdn, candidate), "."), candidate
		}
	}
	domain = util.UnFqdn(resolvedZone)
	klog.Warningf("No zone hosted on arvan matched %s, falling back to %s", fqdn, domain)
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, domain), "."), domain
}

// zoneExists reports whether the account hosts the given zone. It asks for the
// dns-records of the zone, so it needs no endpoint beyond the ones this
// webhook already uses. Anything other than a 200 means the zone is not usable
// here, so the next candidate is tried.
func (c *arvanDNSProviderSolver) zoneExists(cfg *arvanDNSProviderConfig, apiSecret, zone string) bool {
	resp, err := resty.New().R().
		SetAuthToken(apiSecret).
		SetAuthScheme("Apikey").
		SetHeader("Accept", "application/json").
		SetQueryString("page=1&per_page=1").
		Get(
			c.urlFactory(
				cfg,
				"/cdn/4.0/domains/{domain}/dns-records",
				"{domain}", zone,
			))
	if err != nil {
		klog.Warningf("Could not check whether zone %s is hosted on arvan: %v", zone, err)
		return false
	}
	return resp.StatusCode() == 200
}

// maxRecordPages caps pagination so a very large zone cannot spin forever.
const maxRecordPages = 20

// findRecordID returns the id of the TXT record of the zone that carries this
// record name and this challenge's key. An empty id means there is no such
// record.
//
// The zone is listed and filtered here rather than through the api's `search`
// parameter: that search has been observed returning no rows for a record that
// exists, which silently turns cleanup into a no-op and leaves the record
// behind. Matching on the exact name and the key also keeps a wildcard and its
// base domain, which are validated through the same record name at the same
// time, from deleting each other's record.
func (c *arvanDNSProviderSolver) findRecordID(cfg *arvanDNSProviderConfig, apiSecret, domain, recordName, key string) (string, error) {
	client := resty.New()

	for page := 1; page <= maxRecordPages; page++ {
		resp, err := client.R().
			SetAuthToken(apiSecret).
			SetAuthScheme("Apikey").
			SetHeader("Accept", "application/json").
			SetQueryString(fmt.Sprintf("page=%d&per_page=100", page)).
			Get(
				c.urlFactory(
					cfg,
					"/cdn/4.0/domains/{domain}/dns-records",
					"{domain}", domain,
				))
		if err != nil {
			klog.Error(err)
			return "", err
		}
		// Request.Header is deliberately not logged: it carries the api key.
		klog.Info(resp.Request.URL, resp.StatusCode())

		if resp.StatusCode() != 200 {
			err = fmt.Errorf("Error listing dns records of %s: %s", domain, string(resp.Body()))
			klog.Error(err)
			return "", err
		}

		recs := DNSRecords{}
		if err := json.Unmarshal(resp.Body(), &recs); err != nil {
			klog.Error(err)
			return "", err
		}

		for _, rec := range recs.Data {
			if strings.EqualFold(rec.Type, "TXT") && strings.EqualFold(rec.Name, recordName) && rec.Text() == key {
				return rec.ID, nil
			}
		}

		if len(recs.Data) == 0 || page >= recs.Meta.LastPage {
			break
		}
	}
	return "", nil
}
