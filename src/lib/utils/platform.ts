/**
 * Whether Reach runs on a phone or tablet (Android today). The system manages
 * windows there, so desktop-only chrome — minimize, maximize, close — has no
 * job to do. Read from the WebView's user agent, which Android's WebView
 * always marks; false while prerendering, where there is no navigator.
 */
export const isMobile: boolean =
	typeof navigator !== 'undefined' && /Android|iPhone|iPad/i.test(navigator.userAgent);
