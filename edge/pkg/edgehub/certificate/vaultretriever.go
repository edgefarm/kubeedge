package certificate

import (
	"github.com/edgefarm/vault-integration/pkg/certretrieval"
	"github.com/kubeedge/kubeedge/pkg/apis/componentconfig/edgecore/v1alpha1"
)

func NewVaultRetriever(config v1alpha1.EdgeHub) (*VaultRetriever, error) {
	retriever, err := certretrieval.New(certretrieval.Config{
		Tokenfile:   config.Vault.TokenFile,
		Vault:       config.Vault.Vault,
		ServerCA:    config.TLSCAFile,
		Role:        config.Vault.Role,
		Name:        config.Vault.CommonName,
		TTL:         config.Vault.TTL,
		Force:       true,
		OutCAfile:   config.TLSCAFile,
		OutCertfile: config.TLSCertFile,
		OutKeyfile:  config.TLSPrivateKeyFile,
		// 20% buffer for
		ValidityCheckTolerance: 80,
	})
	if err != nil {
		return nil, err
	}
	return &VaultRetriever{*retriever}, nil
}

type VaultRetriever struct {
	certRetrieval certretrieval.CertRetrieval
}

func (vr *VaultRetriever) RetrieveCertificate() error {
	return vr.certRetrieval.Retrieve()
}
