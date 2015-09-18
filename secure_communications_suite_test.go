package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestSecureCommunications(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SecureCommunications Suite")
}
