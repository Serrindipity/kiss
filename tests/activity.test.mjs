import test from 'node:test';
import assert from 'node:assert/strict';
import { activityDetail, actionText, groupActivity, hostHue, relativeTime } from '../src/activity.js';

test('relative timestamps handle singulars, older events, and clock skew', () => {
  const now = 200000000;
  assert.equal(relativeTime(now / 1000 + 10, now), 'just now');
  assert.equal(relativeTime(now / 1000 - 60, now), '1 minute ago');
  assert.equal(relativeTime(now / 1000 - 180, now), '3 minutes ago');
  assert.equal(relativeTime(now / 1000 - 7200, now), '2 hours ago');
  assert.equal(relativeTime(now / 1000 - 86400, now), '1 day ago');
});

test('each scan has its own group, preserving the actors and transitions', () => {
  const event = (id, status, at, actor = 'sohee') => ({ id, action: `port scan ${status}`, kind: 'host', target_id: 'box', label: 'webhost', at, actor, detail: '7 open TCP ports found on 10.0.0.1. Results imported.' });
  const events = [event('4', 'cancelled', 4, 'alex'), event('3', 'queued', 3), event('2', 'complete', 2), event('1', 'queued', 1)];
  const grouped = groupActivity(events);
  assert.equal(grouped.length, 2);
  assert.deepEqual(grouped[0].history.map(e => e.id), ['3', '4']);
  assert.equal(grouped[0].actor, 'alex');
  assert.equal(grouped[1].id, '1');
  assert.equal(actionText(grouped[1]), 'finished scanning');
  assert.equal(activityDetail(grouped[1]), 'Found 7 open TCP ports');
  assert.equal(events[0].id, '4');
  assert.equal(groupActivity([events[0]])[0].history.length, 1);
});

test('host hues remain stable and within the restrained palette', () => {
  assert.equal(hostHue('box'), hostHue('box'));
  for (const id of ['box', 'webhost', 'dc01']) assert.ok(hostHue(id) >= 155 && hostHue(id) <= 300);
});
