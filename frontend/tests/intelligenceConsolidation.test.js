import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import {
  ADMIN_SELECT_SERVER_MESSAGE,
  adminRunDetectionBlocked,
  cloudDetectionUnsupportedMessage,
  detectionReadyLabel,
  detectionRunFeedback,
  hybridRunMessage,
} from '../src/detection/detectionPanel.js'
import { CLOUD, LINUX, isRouteAllowed, navForEnvironment, routeEnvironment, switchTargetPath } from '../src/environment.js'
import { combinedLinuxCollectionMessage, formatLinuxCollectionFeedback } from '../src/servers/collectionFeedback.js'

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')

describe('Detection → Intelligence consolidation', () => {
  it('shows a single DefenSync Intelligence nav entry and no Detection entry', () => {
    const linux = navForEnvironment(LINUX).map((item) => item.label)
    const cloud = navForEnvironment(CLOUD).map((item) => item.label)
    assert.deepEqual(linux.filter((label) => label === 'DefenSync Intelligence'), ['DefenSync Intelligence'])
    assert.ok(!linux.includes('Detection'))
    assert.ok(!cloud.includes('Detection'))
    assert.ok(cloud.includes('DefenSync Intelligence'))
  })

  it('redirects the old Detection route to Intelligence', () => {
    assert.equal(routeEnvironment('/detection'), null)
    assert.ok(isRouteAllowed('/detection', LINUX) && isRouteAllowed('/detection', CLOUD))
    assert.equal(switchTargetPath('/detection', CLOUD), '/detection')

    const app = source('App.jsx')
    assert.match(app, /path="detection" element={<Navigate to="\/intelligence" replace \/>}/)
    assert.doesNotMatch(app, /import Detection from/)
    assert.doesNotMatch(app, /pages\/Detection/)
  })

  it('Intelligence embeds DetectionPanel without a manual Run Detection button', () => {
    const page = source('pages/Intelligence.jsx')
    const panel = source('components/intelligence/DetectionPanel.jsx')
    assert.match(page, /DetectionPanel/)
    assert.match(page, /DefenSync Intelligence/)
    assert.match(page, /runCorrelation/)
    assert.match(page, /getIncidents/)
    assert.match(page, /ActiveInvestigation|ThreatInvestigation/)
    assert.match(page, /SecurityRecommendation/)
    assert.match(page, /resolvePrimarySecurityScore/)
    assert.match(page, /getDashboardSummary/)
    assert.match(page, /data-primary-security-score/)
    assert.match(page, /data-investigation-confidence/)
    assert.doesNotMatch(page, /RiskWidget/)
    assert.doesNotMatch(page, /Typing Speed|Command Rate|Idle Time|Session Duration/)
    assert.doesNotMatch(page, /GLOBAL SECURITY INTELLIGENCE|Behavioral context|Activity trend|data-activity-trend/)
    assert.doesNotMatch(page, /Load Behavioral Demo Data|BGL \/ HPC|My profiles/)
    assert.doesNotMatch(page, /title="Cloud Activity"|function CloudActivity|VM Activity|No OpenStack records/)
    assert.doesNotMatch(page, /label: 'OpenStack'|label: 'HDFS'|Synthetic Demo/)
    assert.match(page, /title="Live activity"|UnifiedEventStream/)
    assert.match(source('environment.js'), /Cloud Accounts/)
    assert.match(source('pages/CloudAccounts.jsx'), /Collect Now|Test Connection/)
    const dashboard = source('pages/Dashboard.jsx')
    assert.doesNotMatch(dashboard, /GLOBAL SECURITY INTELLIGENCE|getGlobalIntelligenceSummary|Synthetic Demo/)
    assert.match(panel, /getDetectionStatus/)
    assert.match(panel, /data-refresh-detection/)
    assert.match(panel, /data-detection-ops-metrics/)
    assert.match(panel, /runs automatically after a successful Linux collection/)
    assert.match(panel, /createQueuedDetectionRefreshController/)
    assert.match(panel, /handleDataRefresh/)
    assert.doesNotMatch(panel, /getAnomalies/)
    assert.doesNotMatch(panel, /predictionsEmptyGuidance|linuxModelView|Recent predictions/)
    assert.doesNotMatch(panel, /label="Engine"|label="Stored predictions"/)
    assert.doesNotMatch(panel, /Linux Isolation Forest|Linux Random Forest/)
    assert.match(panel, /label="Events in DB"|label="Open alerts"/)
    assert.doesNotMatch(panel, /runDetection/)
    assert.doesNotMatch(panel, /data-run-detection/)
    assert.doesNotMatch(panel, /Run Detection/)
    assert.match(panel, /if \(!isLinux\)/)
    assert.match(panel, /cloudDetectionUnsupportedMessage/)
    assert.doesNotMatch(panel, /PIPELINE/)
  })

  it('formats detection status and run results without inventing success', () => {
    assert.equal(detectionReadyLabel(null).value, 'Unknown')
    assert.equal(detectionReadyLabel({ ready: false }).value, 'Not ready')
    assert.equal(detectionReadyLabel({ ready: true, random_forest: 'trained' }).value, 'Ready')
    const linuxNotReady = detectionReadyLabel({
      ready: false,
      linux: {
        eligible_count: 47,
        minimum_required: 100,
        training_status: 'not_trained',
        model_present: false,
        isolation_forest_status: 'insufficient_baseline',
      },
    })
    assert.equal(linuxNotReady.value, 'Not ready')
    assert.match(linuxNotReady.caption, /53 more eligible LIVE_LINUX/)
    assert.match(linuxNotReady.caption, /47\/100/)
    assert.doesNotMatch(linuxNotReady.caption, /Ready/)
    assert.match(hybridRunMessage({ events_analyzed: 12, isolation_forest: 'trained', random_forest: 'no_valid_labels', linux: { eligible_count: 12, minimum_required: 100, anomaly_count: 0 } }), /Analyzed 12/)
    assert.match(hybridRunMessage({ events_analyzed: 3, isolation_forest: 'insufficient_events', linux: { scored_count: 0 } }), /below the minimum/)
    assert.match(cloudDetectionUnsupportedMessage(), /not the Linux detection endpoints/i)
  })

  it('preserves admin/server helper semantics even without a manual Run Detection button', () => {
    assert.equal(ADMIN_SELECT_SERVER_MESSAGE, 'Select a server before running detection as an administrator.')
    assert.equal(adminRunDetectionBlocked(true, null), true)
    assert.equal(adminRunDetectionBlocked(true, ''), true)
    assert.equal(adminRunDetectionBlocked(true, 'server-1'), false)
    assert.equal(adminRunDetectionBlocked(false, null), false)
    assert.equal(adminRunDetectionBlocked(false, 'server-1'), false)

    const panel = source('components/intelligence/DetectionPanel.jsx')
    assert.doesNotMatch(panel, /adminRunDetectionBlocked/)
    assert.doesNotMatch(panel, /ADMIN_SELECT_SERVER_MESSAGE/)
    assert.doesNotMatch(panel, /useAuth/)
  })

  it('prefers backend detection messages and treats success:false as a warning', () => {
    const backendText = 'Linux Isolation Forest not trained: 12 eligible. Cloud/HPC/behavioral: Detection skipped.'
    const fromBackend = detectionRunFeedback({
      success: true,
      message: backendText,
      isolation_forest: 'insufficient_events',
      events_analyzed: 3,
    })
    assert.equal(fromBackend.message, backendText)
    assert.equal(fromBackend.type, 'info')

    const failed = detectionRunFeedback({
      success: false,
      message: 'Detection could not complete for this scope.',
      events_analyzed: 0,
    })
    assert.equal(failed.message, 'Detection could not complete for this scope.')
    assert.equal(failed.type, 'warning')

    const fallback = detectionRunFeedback({
      success: true,
      events_analyzed: 3,
      isolation_forest: 'insufficient_events',
      linux: { scored_count: 0 },
    })
    assert.match(fallback.message, /below the minimum/)
    assert.equal(fallback.type, 'info')
  })

  it('separates collection success from queued detection messaging', () => {
    const ok = formatLinuxCollectionFeedback('ubuntu-web', {
      success: true,
      collected_events: 4,
      detection: { status: 'queued', message: 'Detection started in the background for this server.' },
    })
    assert.equal(ok.collection, 'ubuntu-web: collected 4 events')
    assert.match(ok.detection, /background/)
    assert.match(
      combinedLinuxCollectionMessage('ubuntu-web', {
        success: true,
        inserted: 2,
        detection: { message: 'Detection started in the background for this server.' },
        collection_n8n: { dispatch_status: 'SKIPPED', sequence_number: 1 },
      }),
      /collected 2 events\. Detection:.*n8n: skipped \(collection #1/,
    )

    const failed = formatLinuxCollectionFeedback('ubuntu-web', { success: false, message: 'SSH failed' })
    assert.equal(failed.collection, 'ubuntu-web: SSH failed')
    assert.equal(failed.detection, null)
    assert.equal(failed.n8n, null)

    const servers = source('pages/Servers.jsx')
    const collection = source('pages/Collection.jsx')
    assert.match(servers, /combinedLinuxCollectionMessage/)
    assert.match(collection, /Detection: \$\{result\.detection\.message\}/)
  })

  it('Layout no longer registers a Detection nav icon', () => {
    const layout = source('components/Layout.jsx')
    assert.doesNotMatch(layout, /detection:\s/)
    assert.match(layout, /intelligence:\s*Network/)
  })
})
