// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from 'vitest';
import axe, { type Result } from 'axe-core';
import { mount } from './main';

// jsdom/happy-dom cannot compute layout, so axe's color-contrast rule cannot run
// here (it is verified visually / by Lighthouse in a real browser). Every other
// WCAG 2 A/AA structural rule runs against the live rendered DOM.
const runAxe = () =>
  axe.run(document.body, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] },
    resultTypes: ['violations'],
    rules: { 'color-contrast': { enabled: false } }
  });

const formatViolations = (violations: Result[]): string =>
  violations
    .map(
      (v) =>
        `${v.id} (${v.impact ?? 'n/a'}): ${v.help}\n  ` +
        v.nodes.map((n) => n.target.join(' ')).join('\n  ')
    )
    .join('\n');

describe('accessibility (axe-core, WCAG 2 A/AA)', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.innerHTML = '<div id="app"></div>';
    mount();
  });

  it('has no violations on the initial render', async () => {
    const { violations } = await runAxe();
    expect(formatViolations(violations)).toBe('');
  });

  it('has no violations after distributed key generation', async () => {
    document.querySelector<HTMLButtonElement>('#run-dkg')!.click();
    const { violations } = await runAxe();
    expect(formatViolations(violations)).toBe('');
  });

  it('has no violations in the light theme', async () => {
    document.documentElement.setAttribute('data-theme', 'light');
    mount();
    const { violations } = await runAxe();
    expect(formatViolations(violations)).toBe('');
  });
});
