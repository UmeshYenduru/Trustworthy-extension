document.getElementById("check-btn").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0].url;
  
      chrome.runtime.sendMessage(
        { action: "checkTrustworthiness", url },
        (response) => {
          const status = document.getElementById("status");
          const scores = response.scores;
          const details = response.details;
  
          if (response.safe) {
            status.textContent = "This website is safe!";
            status.style.color = "green";
          } else {
            status.textContent = "Warning! This website may not be safe.";
            status.style.color = "red";
          }
  
          // Display detailed results with scores
          const detailDiv = document.getElementById("details");
          detailDiv.innerHTML = `
            <p><strong>SSL Check:</strong> ${details.sslStatus.message} (Score: ${scores.ssl}/25)</p>
            <p><strong>Reputation Check:</strong> ${details.reputation.message} (Score: ${scores.reputation}/30)</p>
            <p><strong>Phishing Check:</strong> ${details.phishing.message} (Score: ${scores.phishing}/25)</p>
            <p><strong>Blacklist Check:</strong> ${details.blacklist.message} (Score: ${scores.blacklist}/20)</p>
            <p><strong>Total Score:</strong> ${response.totalScore}/100</p>
          `;
        }
      );
    });
  });
  