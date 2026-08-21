import sys
sys.stdout.reconfigure(encoding='utf-8')
from app.api.chatbot import match_knowledge_base, synthesize_comprehensive_answer

queries = [
    'What is SQL injection and how does it compromise databases?',
    'What is Cross-Site Scripting (XSS)?',
    'How do I secure my home wifi and router from hackers?',
    'What is Zero Trust security architecture?',
    'Can someone hack my phone by sending a link on WhatsApp?',
    'What is the difference between phishing, smishing, and vishing?',
    'What is the difference between symmetric and asymmetric encryption?',
    'Why is HTTPS alone not sufficient to guarantee a website is safe?',
    'Can you tell me how hackers use evilproxy to bypass 2fa?',
    'What should I do if I accidentally entered my password on a phishing site?'
]

print("=== RUNNING FAST CHATBOT REASONING TESTS ===")
for i, q in enumerate(queries, 1):
    matched = match_knowledge_base(q)
    reply, actions = synthesize_comprehensive_answer(q, matched)
    assert len(reply) > 100, f"Reply too short: {reply}"
    assert len(actions) > 0, "No suggested actions returned"
    print(f"[{i}] Q: \"{q}\" -> Success ({len(reply)} chars, {len(actions)} actions)")

print("\n🎉 ALL 10 CHATBOT REASONING TESTS PASSED PERFECTLY!")
