// SPDX-License-Identifier: Apache-2.0
// React 薄壳：<HHubRisk endpoint="https://risk.example.com" onReady={tok => ...} />
// 依赖：React 18+；hhub-risk.js 需先以 <script> 引入（或自行 import 后挂到 window）。
import { useEffect, useState } from 'react';

export function HHubRisk({ endpoint, onReady, onError, children }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    const sdk = window.HHubRisk;
    if (!sdk) {
      setError(new Error('缺少 hhub-risk.js'));
      onError && onError(new Error('缺少 hhub-risk.js'));
      return;
    }
    sdk.init({ endpoint })
      .then((t) => {
        if (!alive) return;
        setToken(t);
        onReady && onReady(t, sdk.last());
      })
      .catch((e) => {
        if (!alive) return;
        setError(e);
        onError && onError(e);
      });
    return () => { alive = false; };
  }, [endpoint]);

  if (children) return children({ token, error });
  return null;
}

export default HHubRisk;
