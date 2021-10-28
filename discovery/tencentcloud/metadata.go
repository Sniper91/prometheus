// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tencentcloud

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

const metaEndpoint = "http://metadata.tencentyun.com/latest/meta-data"

// MetaClient represents CVM meta data client.
type MetaClient struct {
	c *http.Client
}

// NewClient creates a MetaClient instance.
func NewClient(timeout time.Duration) *MetaClient {
	return &MetaClient{
		c: &http.Client{Timeout: timeout},
	}
}

// GetRegion returns CVM region.
func (mc *MetaClient) GetRegion() (string, error) {
	r, err := mc.getResponse("/placement/region")
	return string(r), err
}

func (mc *MetaClient) getResponse(subPath string) ([]byte, error) {
	url := metaEndpoint + subPath
	httpResp, err := mc.c.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(ioutil.Discard, httpResp.Body)
		httpResp.Body.Close()
	}()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s return %d", url, httpResp.StatusCode)
	}
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
