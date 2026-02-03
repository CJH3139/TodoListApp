const path = require('path');
const express = require('express');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname)));

app.post('/api/parse-task', async (req, res) => {
  try {
    const { text, section, category, today } = req.body || {};
    if (!text || typeof text !== 'string') {
      return res.status(400).send('Missing text.');
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(500).send('Missing OPENAI_API_KEY.');
    }

    const systemPrompt = [
      'You convert a spoken task into structured JSON for a todo app.',
      'Rules:',
      '- Always return valid JSON that matches the schema exactly.',
      '- Use YYYY-MM-DD for date. If no date is given, use today.',
      '- If a date is given without a year, assume the current year based on "today".',
      '- Priority is 1-5. Map phrases like "low/pretty low" => 2, "medium" => 3, "high/urgent" => 5.',
      '- If recurrence is not specified, use "none".',
      '- Keep tags short (0-4).',
      '- Notes should include any extra details not in the title.',
      `Today is ${today || 'unknown'}.`
    ].join('\n');

    const userPrompt = [
      `Section: ${section || 'general'}`,
      `Category: ${category || 'none'}`,
      `User said: ${text}`
    ].join('\n');

    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        input: [
          {
            role: 'system',
            content: [{ type: 'input_text', text: systemPrompt }]
          },
          {
            role: 'user',
            content: [{ type: 'input_text', text: userPrompt }]
          }
        ],
        text: {
          format: {
            type: 'json_schema',
            json_schema: {
              name: 'todo_task',
              strict: true,
              schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  name: { type: 'string' },
                  date: { type: 'string' },
                  priority: { type: 'integer', minimum: 1, maximum: 5 },
                  tags: { type: 'array', items: { type: 'string' } },
                  notes: { type: 'string' },
                  recurrence: {
                    type: 'string',
                    enum: ['none', 'daily', 'weekly', 'monthly']
                  }
                },
                required: ['name', 'date', 'priority', 'tags', 'notes', 'recurrence']
              }
            }
          }
        }
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).send(errorText || 'OpenAI request failed.');
    }

    const data = await response.json();
    const outputText = extractOutputText(data);
    const parsed = JSON.parse(outputText);

    return res.json(parsed);
  } catch (err) {
    return res.status(500).send(err.message || 'Server error.');
  }
});

function extractOutputText(data) {
  if (data && typeof data.output_text === 'string') {
    return data.output_text;
  }
  const parts = [];
  for (const item of data.output || []) {
    if (item.type === 'message') {
      for (const content of item.content || []) {
        if (content.type === 'output_text') {
          parts.push(content.text);
        }
      }
    }
  }
  return parts.join('');
}

app.listen(PORT, () => {
  console.log(`TodoListApp running at http://localhost:${PORT}`);
});
