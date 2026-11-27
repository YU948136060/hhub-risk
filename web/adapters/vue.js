// SPDX-License-Identifier: Apache-2.0
// Vue 3 薄壳（插件）：app.use(HHubRiskPlugin, { endpoint })
// 用法：组件里 inject('hhubRisk') → { token, last, fetch, score }
export const HHubRiskPlugin = {
  install(app, options = {}) {
    const sdk = window.HHubRisk;
    const state = { token: '', last: null, error: null, ready: null };
    if (!sdk) {
      state.error = new Error('缺少 hhub-risk.js');
    } else {
      state.ready = sdk.init({ endpoint: options.endpoint }).then(
        (t) => { state.token = t; state.last = sdk.last(); return t; },
        (e) => { state.error = e; throw e; }
      );
      state.ready.catch(() => {});
    }
    app.provide('hhubRisk', {
      state,
      ready: () => state.ready || Promise.resolve(state.token),
      fetch: (input, init) => (sdk ? sdk.fetch(input, init) : fetch(input, init)),
      score: (telemetry) => (sdk ? sdk.score(telemetry) : Promise.reject(new Error('缺少 hhub-risk.js'))),
    });
  },
};
export default HHubRiskPlugin;
