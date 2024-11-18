const GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCti1KKCa316kwpG7tOJPuHzX0ET0BRpmw";
const VIRUSTOTAL_API_KEY = "2901268424c595e58e40fb239c3708e7019442c45a42f0139578a3d9713516c8";

// Hardcoded blacklist for demonstration
const BLACKLIST = [
  "http://malicious-example.com",
  "https://phishing-example.org",
  "http://unsafe-site.net"
];

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkTrustworthiness") {
    const url = request.url;

    // Perform all checks
    Promise.all([
      checkSSL(url),
      checkURLReputation(url),
      checkPhishing(url),
      checkBlacklist(url)
    ]).then((results) => {
      const [sslStatus, reputation, phishing, blacklist] = results;

      // Calculate scores
      const scores = {
        ssl: sslStatus.safe ? 25 : 0,
        reputation: reputation.safe ? 30 : 0,
        phishing: phishing.safe ? 25 : 0,
        blacklist: blacklist.safe ? 20 : 0,
      };

      const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);

      sendResponse({
        safe: totalScore === 100,
        scores,
        details: { sslStatus, reputation, phishing, blacklist },
        totalScore
      });
    });

    return true; // Keeps the message channel open for async response
  }
});

// SSL Check
async function checkSSL(url) {
  try {
    const protocol = new URL(url).protocol;
    return {
      safe: protocol === "https:",
      message: protocol === "https:" ? "SSL is valid." : "No SSL detected."
    };
  } catch (error) {
    return { safe: false, message: "Error checking SSL." };
  }
}

// URL Reputation Check (VirusTotal)
async function checkURLReputation(url) {
    try {
      // Base64 encode the URL
      const encodedURL = btoa(url);
  
      // API endpoint for checking URL reputation
      const apiUrl = `https://www.virustotal.com/api/v3/urls/${encodedURL}`;
  
      // Make the GET request to the API
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY,
        },
      });
  
      // Check if the response is OK
      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }
  
      // Parse the response JSON
      const data = await response.json();
  
      // Get harmless and malicious stats
      const harmless = data.data.attributes.last_analysis_stats.harmless || 0;
      const malicious = data.data.attributes.last_analysis_stats.malicious || 0;
  
      // Return the result based on malicious count
      return {
        safe: malicious === 0,
        message: malicious === 0
          ? "Reputation is clean."
          : `Reputation flagged as malicious (${malicious} detections).`
      };
    } catch (error) {
      return {
        safe: false,
        message: `Error checking reputation: ${error.message}`,
      };
    }
  }
  

// Phishing Detection (Simple Heuristic)
async function checkPhishing(url) {
  try {
    const response = await fetch(url);
    const text = await response.text();

    // Check for common phishing patterns (simplified example)
    const patterns = ["login", "password", "verify account"];
    const isPhishing = patterns.some((pattern) =>
      text.toLowerCase().includes(pattern)
    );

    return {
      safe: !isPhishing,
      message: isPhishing ? "Potential phishing site detected." : "No phishing signs."
    };
  } catch (error) {
    return { safe: false, message: "Error checking phishing patterns." };
  }
}

// Blacklist Check
async function checkBlacklist(url) {
  const isBlacklisted = BLACKLIST.some((blacklistedUrl) => url.includes(blacklistedUrl));

  return {
    safe: !isBlacklisted,
    message: isBlacklisted ? "URL is blacklisted." : "Not in blacklist."
  };
}
