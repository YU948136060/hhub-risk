// SPDX-License-Identifier: Apache-2.0
// Web Component：<hhub-risk endpoint="https://risk.example.com"></hhub-risk>
// 完成后派发 CustomEvent('hhub-risk-ready', { detail: { token, last } })
// 失败派发 CustomEvent('hhub-risk-error', { detail: { error } })
(function () {
  if (typeof customElements === 'undefined') return;
  class HHubRiskElement extends HTMLElement {
    connectedCallback() {
      const endpoint = this.getAttribute('endpoint') || '';
      const sdk = window.HHubRisk;
      if (!sdk) return this.dispatchEvent(new CustomEvent('hhub-risk-error', { detail: { error: new Error('缺少 hhub-risk.js') } }));
      sdk.init({ endpoint }).then(
        (token) => this.dispatchEvent(new CustomEvent('hhub-risk-ready', { detail: { token, last: sdk.last() } })),
        (error) => this.dispatchEvent(new CustomEvent('hhub-risk-error', { detail: { error } }))
      );
    }
  }
  if (!customElements.get('hhub-risk')) customElements.define('hhub-risk', HHubRiskElement);
})();
