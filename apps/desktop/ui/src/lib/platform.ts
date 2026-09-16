/**
 * Which desktop this interface is running on.
 *
 * Decided from the user agent, because `navigator.platform` is deprecated and
 * `userAgentData` is missing from two of the three WebViews this ships in. Each
 * engine states its operating system plainly there — WebView2 says `Windows
 * NT`, WKWebView says `Macintosh`, WebKitGTK says `X11; Linux` — and nothing
 * else about the string is relied on.
 *
 * Used for behaviour that each platform does its own way and that a user of
 * that platform notices when it is done any other way: which key copies in a
 * terminal, what a right click does, which font a terminal is set in. It is
 * never used to decide what is *allowed*.
 */

export type Platform = "windows" | "macos" | "linux";

export function platformFromUserAgent(userAgent: string): Platform {
  if (/windows/i.test(userAgent)) return "windows";
  if (/mac os|macintosh|iphone|ipad/i.test(userAgent)) return "macos";
  // X11, Wayland and the BSDs all behave as the Linux desktops do here.
  return "linux";
}

export function currentPlatform(): Platform {
  return platformFromUserAgent(typeof navigator === "undefined" ? "" : navigator.userAgent);
}
