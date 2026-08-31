export async function onRequestPost(context) {
  const { request, env } = context;

  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return json({ error: 'ANTHROPIC_API_KEY is not configured on this deployment.' }, 500);
  }

  const apiUrl = env.ANTHROPIC_API_URL || 'https://api.anthropic.com/v1/messages';
  const model = env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514';
  const version = env.ANTHROPIC_VERSION || '2023-06-01';

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body.' }, 400);
  }

  body.model = model;

  try {
    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': version,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return json(data, res.status);
  } catch (e) {
    return json({ error: e.message || 'Upstream request failed.' }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
