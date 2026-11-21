const API_BASE_URL = "http://YOUR-ALB-DNS-NAME.eu-north-1.elb.amazonaws.com";

function onGmailMessageOpen(e) {
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const message = GmailApp.getMessageById(e.gmail.messageId);
  const rawEmail = [
    "From: " + message.getFrom(),
    "Reply-To: " + message.getReplyTo(),
    "Subject: " + message.getSubject(),
    "",
    message.getPlainBody()
  ].join("\n");

  let result;
  try {
    const response = UrlFetchApp.fetch(API_BASE_URL + "/api/scan", {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify({ content: rawEmail, filename: "gmail_inbox_message.eml" }),
      muteHttpExceptions: true
    });
    result = JSON.parse(response.getContentText());
  } catch (err) {
    return buildErrorCard("Could not reach PhishGuard AI API: " + err.message);
  }

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Verdict: " + result.verdict)
      .setSubtitle("Risk Score: " + result.risk_score + "/100 (" + result.risk_level + ")"));

  const section = CardService.newCardSection().setHeader("Detected Indicators");
  if (result.indicators && result.indicators.length > 0) {
    result.indicators.forEach(function (ind) {
      section.addWidget(CardService.newTextParagraph()
        .setText("<b>[" + ind.category + " +" + ind.points + "]</b> " + ind.detail));
    });
  } else {
    section.addWidget(CardService.newTextParagraph().setText("No suspicious indicators detected."));
  }

  return card.addSection(section).build();
}

function buildErrorCard(msg) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Scan Error"))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(msg)))
    .build();
}
