// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from './main';

describe('demo UI wiring', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.innerHTML = '<div id="app"></div>';
    mount(); // resets state and renders against the fresh DOM
  });

  it('renders all five exhibits with the key step locked initially', () => {
    const headings = [...document.querySelectorAll('h2')].map((h) => h.textContent ?? '');
    expect(headings.some((h) => h.includes('Exhibit 1'))).toBe(true);
    expect(headings.some((h) => h.includes('Exhibit 5'))).toBe(true);
    // Encryption panel is locked until keys exist.
    expect(document.querySelector('#encrypt')?.hasAttribute('disabled')).toBe(true);
  });

  it('runs DKG on click, revealing a group key and one node per party', () => {
    document.querySelector<HTMLButtonElement>('#run-dkg')!.click();
    expect(document.querySelectorAll('.distribution .node').length).toBe(5);
    expect(document.querySelector('#copy-key')).not.toBeNull();
    // Encryption is now unlocked.
    expect(document.querySelector('#encrypt')?.hasAttribute('disabled')).toBe(false);
  });

  it('exposes accessible labels, landmarks, and step state', () => {
    expect(document.querySelector('main[role="main"]#main-content')).not.toBeNull();
    expect(document.querySelector('#theme-toggle')?.getAttribute('aria-label')).toBeTruthy();
    // First step is current until keys exist.
    const current = document.querySelector('.steps li[aria-current="step"]');
    expect(current?.textContent).toContain('Generate keys');
    // Range inputs are programmatically labelled.
    for (const id of ['participants', 'threshold', 'compromised']) {
      expect(document.querySelector(`label[for="${id}"]`)).not.toBeNull();
      expect(document.querySelector(`#${id}`)?.getAttribute('aria-valuenow')).not.toBeNull();
    }
  });

  it('labels the copy-key control after DKG', () => {
    document.querySelector<HTMLButtonElement>('#run-dkg')!.click();
    expect(document.querySelector('#copy-key')?.getAttribute('aria-label')).toBeTruthy();
  });

  it('invalidates generated keys when the scheme changes after DKG', () => {
    document.querySelector<HTMLButtonElement>('#run-dkg')!.click();
    expect(document.querySelectorAll('.distribution .node').length).toBe(5);

    const threshold = document.querySelector<HTMLInputElement>('#threshold')!;
    threshold.value = '4';
    threshold.dispatchEvent(new Event('input', { bubbles: true }));

    // Old shares no longer match the new (n, t): keys and downstream steps are cleared.
    expect(document.querySelectorAll('.distribution .node').length).toBe(0);
    expect(document.querySelector('#copy-key')).toBeNull();
    expect(document.querySelector('#encrypt')?.hasAttribute('disabled')).toBe(true);
  });

  it('keeps threshold <= party count when the party slider drops', () => {
    const parties = document.querySelector<HTMLInputElement>('#participants')!;
    const threshold = document.querySelector<HTMLInputElement>('#threshold')!;
    threshold.value = '5';
    threshold.dispatchEvent(new Event('input', { bubbles: true }));
    parties.value = '3';
    parties.dispatchEvent(new Event('input', { bubbles: true }));
    const t = document.querySelector<HTMLInputElement>('#threshold')!;
    expect(Number(t.value)).toBeLessThanOrEqual(3);
  });
});
