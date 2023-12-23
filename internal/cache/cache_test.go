package cache

import (
	"strconv"
	"sync"
	"testing"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/policy-general/internal/shared"
	"github.com/stretchr/testify/assert"
)

// TestCacheSetAndGet tests the Set and Get methods of the
func TestCacheSetAndGet(t *testing.T) {
	assertion := assert.New(t)
	c := NewCache()
	result := shared.ComplianceResult{
		Compliance:         configServiceTypes.ComplianceTypeCompliant,
		PolicyDocumentName: "TestPolicy",
		ResourceArn:        "arn:aws:test::1234567890:testResource",
	}

	testKey := CacheKey{
		PK: "testPK",
		SK: "testSk",
	}
	c.Set(testKey, result)
	gotResult, exists := c.Get(testKey)

	assertion.True(exists)
	assertion.Equal(result, gotResult)
}

// TestCacheGetNonExistingKey tests retrieving a non-existing key from the
func TestCacheGetNonExistingKey(t *testing.T) {
	assertion := assert.New(t)
	c := NewCache()
	nonExistentKey := CacheKey{
		PK: "nonExistingPK",
		SK: "nonExistingSk",
	}
	_, exists := c.Get(nonExistentKey)
	assertion.False(exists)
}

// TestCacheConcurrentAccess tests concurrent access to the
func TestCacheConcurrentAccess(t *testing.T) {
	assertion := assert.New(t)
	c := NewCache()
	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(val int) {
			defer wg.Done()
			key := "key" + strconv.Itoa(val)
			result := shared.ComplianceResult{
				Compliance:         configServiceTypes.ComplianceTypeCompliant,
				PolicyDocumentName: "TestPolicy" + strconv.Itoa(val),
				ResourceArn:        "arn:aws:test::1234567890:testResource" + strconv.Itoa(val),
			}
			c.Set(CacheKey{
				PK: key,
			}, result)
			gotResult, _ := c.Get(CacheKey{
				PK: key,
			})
			assertion.Equal(result, gotResult)
		}(i)
	}

	wg.Wait()
}
