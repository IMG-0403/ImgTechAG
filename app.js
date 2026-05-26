const steps = [
  "User Input",
  "Session / Context",
  "LLM Preprocess",
  "Intent / Entity",
  "Routing",
  "RAG Search",
  "Confidence",
  "Missing Slot",
  "Tool / API",
  "Policy Check",
  "Response",
  "Human Escalation",
  "Logging / Learning",
];

const knowledgeBase = [
  {
    title: "VPN接続後にSMB共有へ接続できない",
    tags: ["vpn", "file server", "network path", "smb"],
    summary:
      "VPN接続中のDNSサフィックス、社内DNS、SMBポート、資格情報キャッシュを順に確認する。",
    score: 0,
  },
  {
    title: "Windows 11 ネットワーク パスが見つかりません",
    tags: ["network path", "dns", "windows 11"],
    summary:
      "UNCパスの名前解決失敗、NetBIOS依存、古いドライブ割り当て、VPN分割トンネル設定が原因になりやすい。",
    score: 0,
  },
  {
    title: "Teamsは使えるが社内リソースだけ失敗する",
    tags: ["teams", "vpn", "split tunnel", "proxy"],
    summary:
      "インターネット通信と社内向け経路は別経路。VPNクライアントのルート配布とDNSを確認する。",
    score: 0,
  },
  {
    title: "BitLocker回復キー要求の一次対応",
    tags: ["bitlocker", "recovery key", "boot"],
    summary:
      "回復キー保管場所、直前のBIOS変更、TPM状態、IntuneまたはEntra IDの登録状態を確認する。",
    score: 0,
  },
  {
    title: "Windows Update失敗時の基本切り分け",
    tags: ["update", "wuauserv", "dism", "sfc"],
    summary:
      "空き容量、サービス状態、DISM、SFC、更新キャッシュの順でリスクの低い確認から進める。",
    score: 0,
  },
];

const toolCatalog = {
  network: [
    ["DNS疎通確認", "Resolve-DnsName fileserver.contoso.local"],
    ["経路確認", "Test-NetConnection fileserver.contoso.local -Port 445"],
    ["VPN状態取得", "Get-NetIPConfiguration と VPNクライアントログを確認"],
  ],
  update: [
    ["更新サービス確認", "Get-Service wuauserv,bits"],
    ["システム修復", "DISM /Online /Cleanup-Image /RestoreHealth"],
  ],
  security: [
    ["BitLocker状態", "manage-bde -status"],
    ["TPM状態", "Get-Tpm"],
  ],
  general: [["イベント確認", "Event Viewer または Get-WinEvent で関連ログを確認"]],
};

const state = {
  turns: 0,
  caseCounter: 1,
};

const els = {
  pipelineSteps: document.querySelector("#pipelineSteps"),
  processBtn: document.querySelector("#processBtn"),
  runDemoBtn: document.querySelector("#runDemoBtn"),
  newCaseBtn: document.querySelector("#newCaseBtn"),
  issueInput: document.querySelector("#issueInput"),
  osSelect: document.querySelector("#osSelect"),
  severitySelect: document.querySelector("#severitySelect"),
  userTypeSelect: document.querySelector("#userTypeSelect"),
  caseId: document.querySelector("#caseId"),
  statusPill: document.querySelector("#statusPill"),
  ctxUser: document.querySelector("#ctxUser"),
  ctxOs: document.querySelector("#ctxOs"),
  ctxTurns: document.querySelector("#ctxTurns"),
  ctxRoute: document.querySelector("#ctxRoute"),
  confidenceValue: document.querySelector("#confidenceValue"),
  confidenceMeter: document.querySelector("#confidenceMeter"),
  confidenceText: document.querySelector("#confidenceText"),
  structuredOutput: document.querySelector("#structuredOutput"),
  ragResults: document.querySelector("#ragResults"),
  missingSlots: document.querySelector("#missingSlots"),
  toolActions: document.querySelector("#toolActions"),
  policyStatus: document.querySelector("#policyStatus"),
  answerOutput: document.querySelector("#answerOutput"),
  auditLog: document.querySelector("#auditLog"),
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[char];
  });
}

function renderPipeline(activeIndex = -1, doneIndex = -1) {
  els.pipelineSteps.innerHTML = steps
    .map((label, index) => {
      const className =
        index === activeIndex ? "pipeline-step active-step" : index <= doneIndex ? "pipeline-step done" : "pipeline-step";
      return `<div class="${className}"><span>[${index + 1}]</span><strong>${label}</strong></div>`;
    })
    .join("");
}

function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function extractIntentAndEntities(text, os, severity, userType) {
  const tokens = tokenize(text);
  const joined = tokens.join(" ");
  const entities = {
    os,
    severity,
    userType,
    errorMessage: text.match(/「(.+?)」/)?.[1] ?? null,
    product: [],
    symptom: [],
  };

  if (/vpn/i.test(text)) entities.product.push("VPN");
  if (/teams/i.test(text)) entities.product.push("Microsoft Teams");
  if (/wi-?fi|wifi/i.test(text)) entities.product.push("Wi-Fi");
  if (/ファイルサーバー|file server|smb|共有|unc/i.test(text)) entities.product.push("File Server / SMB");
  if (/bitlocker/i.test(text)) entities.product.push("BitLocker");
  if (/update|更新/i.test(text)) entities.product.push("Windows Update");

  if (/アクセスでき|接続でき|見つかりません|失敗|エラー/i.test(text)) {
    entities.symptom.push("connection_failure");
  }
  if (/遅い|重い/i.test(text)) entities.symptom.push("performance_degradation");

  let intent = "general_troubleshooting";
  if (joined.includes("vpn") || /ファイルサーバー|ネットワーク パス|smb|共有/.test(text)) {
    intent = "network_resource_access";
  } else if (/bitlocker|回復キー/i.test(text)) {
    intent = "endpoint_security_recovery";
  } else if (/update|更新/i.test(text)) {
    intent = "windows_update_repair";
  }

  return { intent, entities };
}

function routeForIntent(intent) {
  return {
    network_resource_access: "Network / VPN",
    endpoint_security_recovery: "Security / Device",
    windows_update_repair: "OS Maintenance",
    general_troubleshooting: "General Support",
  }[intent];
}

function searchKnowledge(text, intent) {
  const queryTokens = new Set(tokenize(`${text} ${intent}`));
  return knowledgeBase
    .map((item) => {
      const tagHits = item.tags.filter((tag) => {
        const parts = tokenize(tag);
        return parts.some((part) => queryTokens.has(part));
      }).length;
      const titleHits = tokenize(item.title).filter((token) => queryTokens.has(token)).length;
      return { ...item, score: Math.min(98, 45 + tagHits * 14 + titleHits * 4) };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);
}

function detectMissingSlots(intent, entities, text) {
  const slots = [];
  if (intent === "network_resource_access") {
    if (!/有線|wi-?fi|wifi/i.test(text)) slots.push("接続方式が未確認です。Wi-Fi、有線、テザリングのどれかを確認してください。");
    if (!/他のユーザー|別端末|全員|自分だけ/i.test(text)) {
      slots.push("影響範囲が未確認です。本人のみか、複数ユーザーで発生しているか確認してください。");
    }
    if (!/\\\\|fileserver|ファイルサーバー/i.test(text)) {
      slots.push("対象サーバー名またはUNCパスが未確認です。");
    }
  }
  if (entities.errorMessage === null) {
    slots.push("画面に表示された正確なエラーメッセージを確認してください。");
  }
  return slots;
}

function confidenceScore(ragResults, missingSlots, severity) {
  const base = ragResults[0]?.score ?? 50;
  const slotPenalty = missingSlots.length * 8;
  const severityPenalty = severity === "Critical" ? 8 : severity === "High" ? 4 : 0;
  return Math.max(35, Math.min(96, base - slotPenalty - severityPenalty));
}

function toolsForIntent(intent) {
  if (intent === "network_resource_access") return toolCatalog.network;
  if (intent === "windows_update_repair") return toolCatalog.update;
  if (intent === "endpoint_security_recovery") return toolCatalog.security;
  return toolCatalog.general;
}

function buildAnswer(intent, route, entities, ragResults, missingSlots, confidence) {
  const needsEscalation = confidence < 65 || entities.severity === "Critical";
  const firstDoc = escapeHtml(ragResults[0]?.title ?? "該当ナレッジなし");
  const safeRoute = escapeHtml(route);
  const safeProducts = escapeHtml(entities.product.join(", ") || "未特定");
  const errorLine = entities.errorMessage ? `エラー「${escapeHtml(entities.errorMessage)}」` : "表示エラー";

  if (intent === "network_resource_access") {
    return `
      <h4>回答案</h4>
      <p>VPN接続後に社内ファイルサーバーだけ接続できない状況として扱います。Teamsが使えているため、インターネット接続そのものよりも、VPN経由の社内DNS、経路、SMB通信の切り分けを優先します。</p>
      <ol>
        <li>VPNを接続した状態で、対象ファイルサーバー名が名前解決できるか確認してください。</li>
        <li>対象サーバーのTCP 445番ポートへ到達できるか確認してください。</li>
        <li>UNCパスをサーバー名ではなくFQDNで試してください。例: \\\\server.example.local\\share</li>
        <li>資格情報マネージャーに古い社内アカウント情報が残っていないか確認してください。</li>
        <li>複数ユーザーで同時発生している場合は、VPN側のDNS配布またはルート配布の障害としてネットワーク担当へ連携してください。</li>
      </ol>
      <p>根拠ナレッジ: ${firstDoc}。ルート: ${safeRoute}。検出した主な情報: ${safeProducts} / ${errorLine}。</p>
      ${needsEscalation ? "<p><strong>人手対応推奨:</strong> 情報不足または重要度が高いため、追加確認後に二次サポートへ連携してください。</p>" : ""}
    `;
  }

  return `
    <h4>回答案</h4>
    <p>${safeRoute} の問い合わせとして分類しました。安全性の高い確認から順に実施し、影響範囲と正確なエラー内容を補足してください。</p>
    <p>根拠ナレッジ: ${firstDoc}。不足情報: ${missingSlots.length ? missingSlots.length + "件" : "なし"}。</p>
  `;
}

function policyCheck(answerHtml) {
  const blocked = [/format c:/i, /disable.*firewall/i, /reg delete/i].some((pattern) => pattern.test(answerHtml));
  return {
    ok: !blocked,
    label: blocked ? "要修正" : "Passed",
  };
}

function addLog(message) {
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString("ja-JP")} ${message}`;
  els.auditLog.prepend(item);
}

function setConfidence(score) {
  els.confidenceValue.textContent = `${score}%`;
  els.confidenceMeter.style.width = `${score}%`;
  els.confidenceMeter.style.background = score >= 78 ? "var(--ok)" : score >= 65 ? "var(--warn)" : "var(--accent)";
  els.confidenceText.textContent =
    score >= 78
      ? "自動回答に十分な根拠があります。"
      : score >= 65
        ? "追加確認を含めた回答が適切です。"
        : "人手エスカレーションを推奨します。";
}

function renderResults(result) {
  els.ctxUser.textContent = result.context.userType;
  els.ctxOs.textContent = result.context.os;
  els.ctxTurns.textContent = `${state.turns} turns`;
  els.ctxRoute.textContent = result.route;
  els.statusPill.textContent = "処理完了";

  els.structuredOutput.textContent = JSON.stringify(
    {
      session: result.context,
      normalizedInput: result.normalizedInput,
      intent: result.intent,
      entities: result.entities,
      route: result.route,
    },
    null,
    2,
  );

  els.ragResults.innerHTML = result.ragResults
    .map(
      (item) => `
        <article class="rag-item">
          <h4>${escapeHtml(item.title)}</h4>
          <p>${escapeHtml(item.summary)}</p>
          <strong>score ${item.score}</strong>
        </article>
      `,
    )
    .join("");

  els.missingSlots.innerHTML = result.missingSlots.length
    ? result.missingSlots.map((slot) => `<li>${escapeHtml(slot)}</li>`).join("")
    : "<li>追加確認なし。回答生成へ進めます。</li>";

  els.toolActions.innerHTML = result.tools
    .map(
      ([title, command]) => `
        <article class="tool-item">
          <h4>${escapeHtml(title)}</h4>
          <p>${escapeHtml(command)}</p>
        </article>
      `,
    )
    .join("");

  els.answerOutput.innerHTML = result.answer;
  els.policyStatus.textContent = result.policy.label;
  els.policyStatus.style.color = result.policy.ok ? "var(--ok)" : "var(--accent)";
  setConfidence(result.confidence);
}

async function runPipeline() {
  state.turns += 1;
  els.statusPill.textContent = "処理中";
  els.policyStatus.textContent = "検査中";
  addLog("ユーザー入力を受信しました。");

  for (let index = 0; index < steps.length; index += 1) {
    renderPipeline(index, index - 1);
    await new Promise((resolve) => setTimeout(resolve, index < 2 ? 120 : 70));
  }

  const text = els.issueInput.value.trim();
  const context = {
    caseId: els.caseId.textContent,
    os: els.osSelect.value,
    severity: els.severitySelect.value,
    userType: els.userTypeSelect.value,
    locale: "ja-JP",
  };
  const normalizedInput = text.replace(/\s+/g, " ");
  const { intent, entities } = extractIntentAndEntities(text, context.os, context.severity, context.userType);
  const route = routeForIntent(intent);
  const ragResults = searchKnowledge(text, intent);
  const missingSlots = detectMissingSlots(intent, entities, text);
  const confidence = confidenceScore(ragResults, missingSlots, context.severity);
  const tools = toolsForIntent(intent);
  const answer = buildAnswer(intent, route, entities, ragResults, missingSlots, confidence);
  const policy = policyCheck(answer);

  renderPipeline(-1, steps.length - 1);
  renderResults({
    context,
    normalizedInput,
    intent,
    entities,
    route,
    ragResults,
    missingSlots,
    confidence,
    tools,
    answer,
    policy,
  });

  addLog(`${route} にルーティングしました。`);
  addLog(`RAG検索で ${ragResults.length} 件の候補を取得しました。`);
  addLog(confidence < 65 ? "Human Escalation を推奨しました。" : "回答案を生成し、ポリシー検査を通過しました。");
}

function newCase() {
  state.caseCounter += 1;
  state.turns = 0;
  els.caseId.textContent = `CASE-260526-${String(state.caseCounter).padStart(3, "0")}`;
  els.issueInput.value = "";
  els.structuredOutput.textContent = "";
  els.ragResults.innerHTML = "";
  els.missingSlots.innerHTML = "";
  els.toolActions.innerHTML = "";
  els.answerOutput.textContent = "問い合わせを処理すると、ユーザー向け回答案がここに表示されます。";
  els.statusPill.textContent = "待機中";
  els.policyStatus.textContent = "未検査";
  els.ctxTurns.textContent = "0 turns";
  els.ctxRoute.textContent = "未判定";
  els.confidenceValue.textContent = "--%";
  els.confidenceMeter.style.width = "0%";
  els.confidenceText.textContent = "処理後に回答確度を表示します。";
  renderPipeline();
  addLog("新規ケースを作成しました。");
}

function demoRun() {
  els.issueInput.value =
    "Windows 11 のPCで、VPN接続後に社内ファイルサーバーへアクセスできません。Wi-Fiはつながっていて、Teamsは使えます。エラーは「ネットワーク パスが見つかりません」です。";
  els.osSelect.value = "Windows 11";
  els.severitySelect.value = "Medium";
  els.userTypeSelect.value = "Employee";
  runPipeline();
}

els.processBtn.addEventListener("click", runPipeline);
els.runDemoBtn.addEventListener("click", demoRun);
els.newCaseBtn.addEventListener("click", newCase);
els.osSelect.addEventListener("change", () => {
  els.ctxOs.textContent = els.osSelect.value;
});
els.userTypeSelect.addEventListener("change", () => {
  els.ctxUser.textContent = els.userTypeSelect.value;
});

renderPipeline();
els.structuredOutput.textContent = JSON.stringify(
  {
    waitingFor: "Run Agent Pipeline",
    flow: steps,
  },
  null,
  2,
);
