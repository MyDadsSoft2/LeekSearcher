require("dotenv").config();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  PermissionFlagsBits,
  REST,
  Routes,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  AttachmentBuilder,
} = require("discord.js");

// ====== CONFIG (from environment) ======
const {
  BOT_TOKEN,
  CLIENT_ID,
  CLIENT_SECRET,
  OAUTH_REDIRECT_URI,
  GUILD_ID,
  ALERT_CHANNEL_ID,
  VERIFIED_ROLE_ID,
  FLAGGED_ROLE_ID,
  STAFF_ROLE_IDS,
  LEAK_SERVER_IDS,
} = process.env;

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const STAFF_ROLES = (STAFF_ROLE_IDS || "").split(",").map((s) => s.trim()).filter(Boolean);

for (const [k, v] of Object.entries({ BOT_TOKEN, CLIENT_ID, CLIENT_SECRET, OAUTH_REDIRECT_URI, GUILD_ID })) {
  if (!v) {
    console.error(`Missing required env var: ${k}`);
    process.exit(1);
  }
}

// ====== STORAGE ======
// data = { servers: { [serverId]: name }, results: { [userId]: { username, flagged: [{id,name}], checkedAt } } }
let data = { servers: {}, results: {} };
try {
  if (fs.existsSync(DATA_FILE)) data = { ...data, ...JSON.parse(fs.readFileSync(DATA_FILE, "utf8")) };
} catch (err) {
  console.error("Failed to load data file:", err.message);
}
for (const id of (LEAK_SERVER_IDS || "").split(",").map((s) => s.trim()).filter(Boolean)) {
  if (!data.servers[id]) data.servers[id] = "(from env)";
}

function save() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("Failed to save data:", err.message);
  }
}
save();

// ====== OAUTH ======
const pendingStates = new Map(); // state -> { userId, expires }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingStates) if (v.expires < now) pendingStates.delete(k);
}, 5 * 60 * 1000);

function buildAuthUrl(userId) {
  const state = crypto.randomBytes(16).toString("hex");
  pendingStates.set(state, { userId, expires: Date.now() + 10 * 60 * 1000 });
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: OAUTH_REDIRECT_URI,
    scope: "identify guilds",
    state,
  });
  return `https://discord.com/oauth2/authorize?${params}`;
}

async function runCheck(code, state) {
  const entry = pendingStates.get(state);
  pendingStates.delete(state);
  if (!entry || entry.expires < Date.now()) throw new Error("This link expired. Go back to Discord and click Verify again.");

  const tokenRes = await fetch("https://discord.com/api/v10/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: OAUTH_REDIRECT_URI,
    }),
  });
  if (!tokenRes.ok) throw new Error("Discord rejected the authorization. Try again.");
  const { access_token } = await tokenRes.json();
  const headers = { Authorization: `Bearer ${access_token}` };

  try {
    const meRes = await fetch("https://discord.com/api/v10/users/@me", { headers });
    if (!meRes.ok) throw new Error("Could not read your account.");
    const me = await meRes.json();
    if (me.id !== entry.userId)
      throw new Error("Account mismatch. Authorize with the same Discord account you clicked the button with.");

    const guilds = [];
    let after;
    while (true) {
      const url = new URL("https://discord.com/api/v10/users/@me/guilds");
      url.searchParams.set("limit", "200");
      if (after) url.searchParams.set("after", after);
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error("Could not read your server list.");
      const page = await res.json();
      if (!Array.isArray(page)) break;
      guilds.push(...page);
      if (page.length < 200) break;
      after = page[page.length - 1].id;
    }

    const flagged = guilds
      .filter((g) => data.servers[g.id])
      .map((g) => ({ id: g.id, name: g.name }));

    data.results[me.id] = { username: me.username, flagged, checkedAt: Date.now() };
    save();
    return { userId: me.id, flagged };
  } finally {
    // We never keep the user's token
    fetch("https://discord.com/api/v10/oauth2/token/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, token: access_token }),
    }).catch(() => {});
  }
}

async function afterVerification(userId, flagged) {
  try {
    const guild = client.guilds.cache.get(GUILD_ID);
    if (!guild) return;
    const member = await guild.members.fetch(userId).catch(() => null);

    if (flagged.length && ALERT_CHANNEL_ID) {
      const ch = await client.channels.fetch(ALERT_CHANNEL_ID).catch(() => null);
      if (ch && ch.isTextBased()) {
        await ch.send({
          embeds: [
            new EmbedBuilder()
              .setTitle("🚩 Flagged server membership")
              .setColor(0xe53e3e)
              .setDescription(`<@${userId}> is in: ${flagged.map((g) => g.name).join(", ")}`)
              .setFooter({ text: `User ID: ${userId}` })
              .setTimestamp(),
          ],
        });
      }
    }

    if (member) {
      if (flagged.length && FLAGGED_ROLE_ID) await member.roles.add(FLAGGED_ROLE_ID).catch((e) => console.error("flag role:", e.message));
      if (!flagged.length && VERIFIED_ROLE_ID) await member.roles.add(VERIFIED_ROLE_ID).catch((e) => console.error("verified role:", e.message));
    }
  } catch (err) {
    console.error("afterVerification failed:", err.message);
  }
}

// ====== HTTP SERVER ======
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const page = (title, body) =>
  `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
  `<body style="font-family:system-ui,sans-serif;background:#1e1f22;color:#f2f3f5;display:grid;place-items:center;min-height:100vh;margin:0">` +
  `<div style="text-align:center;padding:2rem"><h1>${title}</h1><p>${body}</p></div></body>`;

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname === "/callback") {
      try {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        if (!code || !state) throw new Error("Authorization was cancelled or incomplete.");
        const { userId, flagged } = await runCheck(code, state);
        afterVerification(userId, flagged);
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(page("Verified ✅", "You can close this tab and return to Discord."));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "text/html" });
        return res.end(page("Verification failed", esc(err.message)));
      }
    }

    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("Bot is alive");
  })
  .listen(PORT, "0.0.0.0", () => console.log(`HTTP server listening on ${PORT}`));

// ====== DISCORD CLIENT ======
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
});

function isStaff(member) {
  if (!member) return false;
  if (member.permissions.has(PermissionFlagsBits.ManageGuild)) return true;
  return member.roles.cache.some((r) => STAFF_ROLES.includes(r.id));
}

const commands = [
  new SlashCommandBuilder()
    .setName("panel")
    .setDescription("Post the verification panel in this channel"),
  new SlashCommandBuilder()
    .setName("report")
    .setDescription("Show who is flagged, clean, or unverified across the server"),
  new SlashCommandBuilder()
    .setName("check")
    .setDescription("Show one member's verification result")
    .addUserOption((o) => o.setName("user").setDescription("Member").setRequired(true)),
  new SlashCommandBuilder()
    .setName("clear")
    .setDescription("Clear a member's result so they must verify again")
    .addUserOption((o) => o.setName("user").setDescription("Member").setRequired(true)),
  new SlashCommandBuilder()
    .setName("servers")
    .setDescription("Manage the flagged server list")
    .addSubcommand((s) =>
      s
        .setName("add")
        .setDescription("Add a server to the flagged list")
        .addStringOption((o) => o.setName("id").setDescription("Server ID").setRequired(true))
        .addStringOption((o) => o.setName("name").setDescription("Label for your reference").setRequired(false))
    )
    .addSubcommand((s) =>
      s
        .setName("remove")
        .setDescription("Remove a server from the flagged list")
        .addStringOption((o) => o.setName("id").setDescription("Server ID").setRequired(true))
    )
    .addSubcommand((s) => s.setName("list").setDescription("Show the flagged server list")),
].map((c) => c.setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild).setDMPermission(false).toJSON());

client.once("ready", async () => {
  console.log(`✅ Online as ${client.user.tag}`);
  const rest = new REST().setToken(BOT_TOKEN);
  await rest.put(Routes.applicationGuildCommands(client.user.id, GUILD_ID), { body: commands });
  console.log("Slash commands registered.");
});

function statusLine(r) {
  if (!r) return "⚪ Not verified";
  if (r.flagged.length) return `🚩 Flagged: ${r.flagged.map((g) => g.name).join(", ")}`;
  return "✅ Clean";
}

client.on("interactionCreate", async (interaction) => {
  try {
    // ----- Verify button (anyone) -----
    if (interaction.isButton() && interaction.customId === "verify") {
      if (!Object.keys(data.servers).length)
        return interaction.reply({ content: "Verification isn't set up yet. Contact staff.", ephemeral: true });

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setLabel("Verify with Discord").setStyle(ButtonStyle.Link).setURL(buildAuthUrl(interaction.user.id))
      );
      return interaction.reply({
        content:
          "Click below and authorize with Discord. We read your server list once, compare it against a list of " +
          "known mod-leak servers, and save only whether you matched. We don't keep your login token. " +
          "The link expires in 10 minutes.",
        components: [row],
        ephemeral: true,
      });
    }

    if (!interaction.isChatInputCommand()) return;
    if (!isStaff(interaction.member))
      return interaction.reply({ content: "No permission.", ephemeral: true });

    const name = interaction.commandName;

    // ----- /panel -----
    if (name === "panel") {
      const embed = new EmbedBuilder()
        .setTitle("🔒 Server Verification")
        .setDescription(
          "All members are asked to verify their account.\n\n" +
            "Click **Verify** and authorize with Discord. We check which servers you're in against a list of " +
            "known mod-leak servers. We don't store your login token, and only staff can see results."
        )
        .setColor(0x5865f2);
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId("verify").setLabel("Verify").setEmoji("🔒").setStyle(ButtonStyle.Primary)
      );
      await interaction.channel.send({ embeds: [embed], components: [row] });
      return interaction.reply({ content: "✅ Panel posted.", ephemeral: true });
    }

    // ----- /check -----
    if (name === "check") {
      const user = interaction.options.getUser("user");
      const r = data.results[user.id];
      const when = r ? `\nChecked <t:${Math.floor(r.checkedAt / 1000)}:R>` : "";
      return interaction.reply({ content: `<@${user.id}>: ${statusLine(r)}${when}`, ephemeral: true });
    }

    // ----- /clear -----
    if (name === "clear") {
      const user = interaction.options.getUser("user");
      delete data.results[user.id];
      save();
      return interaction.reply({ content: `Cleared <@${user.id}>. They'll need to verify again.`, ephemeral: true });
    }

    // ----- /servers -----
    if (name === "servers") {
      const sub = interaction.options.getSubcommand();
      if (sub === "add") {
        const id = interaction.options.getString("id").trim();
        if (!/^\d{15,25}$/.test(id))
          return interaction.reply({ content: "That doesn't look like a valid server ID.", ephemeral: true });
        data.servers[id] = interaction.options.getString("name") || "(no label)";
        save();
        return interaction.reply({
          content: `Added \`${id}\`. Members who verified earlier need to re-verify to be checked against it (use /clear or ask them to click Verify again).`,
          ephemeral: true,
        });
      }
      if (sub === "remove") {
        const id = interaction.options.getString("id").trim();
        if (!data.servers[id]) return interaction.reply({ content: "That ID isn't on the list.", ephemeral: true });
        delete data.servers[id];
        save();
        return interaction.reply({ content: `Removed \`${id}\`.`, ephemeral: true });
      }
      const entries = Object.entries(data.servers);
      return interaction.reply({
        content: entries.length ? entries.map(([id, n]) => `\`${id}\` — ${n}`).join("\n").slice(0, 1900) : "The list is empty.",
        ephemeral: true,
      });
    }

    // ----- /report -----
    if (name === "report") {
      await interaction.deferReply({ ephemeral: true });
      const members = await interaction.guild.members.fetch();
      const humans = members.filter((m) => !m.user.bot);

      const flagged = [];
      const clean = [];
      const unverified = [];
      for (const m of humans.values()) {
        const r = data.results[m.id];
        if (!r) unverified.push(m);
        else if (r.flagged.length) flagged.push({ m, r });
        else clean.push(m);
      }

      const lines = [
        `LEAK SERVER REPORT — ${new Date().toISOString()}`,
        `Total: ${humans.size} | Flagged: ${flagged.length} | Clean: ${clean.length} | Unverified: ${unverified.length}`,
        "",
        "=== FLAGGED ===",
        ...flagged.map(({ m, r }) => `${m.user.tag} (${m.id}) — ${r.flagged.map((g) => g.name).join(", ")} — checked ${new Date(r.checkedAt).toISOString()}`),
        "",
        "=== UNVERIFIED ===",
        ...unverified.map((m) => `${m.user.tag} (${m.id})`),
        "",
        "=== CLEAN ===",
        ...clean.map((m) => `${m.user.tag} (${m.id})`),
      ];
      const file = new AttachmentBuilder(Buffer.from(lines.join("\n"), "utf8"), { name: "leak-report.txt" });

      let flaggedText = flagged.length
        ? flagged.map(({ m, r }) => `<@${m.id}> — ${r.flagged.map((g) => g.name).join(", ")}`).join("\n")
        : "None 🎉";
      if (flaggedText.length > 1000) flaggedText = flaggedText.slice(0, 990) + "\n…(see file)";

      const embed = new EmbedBuilder()
        .setTitle("🔍 Leak Server Report")
        .setColor(flagged.length ? 0xe53e3e : 0x38a169)
        .addFields(
          { name: "Members", value: `${humans.size}`, inline: true },
          { name: "✅ Clean", value: `${clean.length}`, inline: true },
          { name: "⚪ Unverified", value: `${unverified.length}`, inline: true },
          { name: `🚩 Flagged (${flagged.length})`, value: flaggedText }
        )
        .setFooter({ text: "Snapshot from when each member last verified." })
        .setTimestamp();

      return interaction.editReply({ embeds: [embed], files: [file] });
    }
  } catch (err) {
    console.error("Interaction error:", err);
    const msg = { content: "Something went wrong.", ephemeral: true };
    if (interaction.deferred || interaction.replied) interaction.editReply(msg).catch(() => {});
    else interaction.reply(msg).catch(() => {});
  }
});

client.login(BOT_TOKEN);
