export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ ok:false, error:"Método não permitido." }); }
  return res.status(200).json({ ok:true, service:"sentinel-api", version:"3.0", timestamp:new Date().toISOString() });
}
