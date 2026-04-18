import { useState, useRef, useEffect } from 'react';
import { chat } from '../api';

export default function ChatPanel({ isOpen, onClose }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEnd = useRef(null);

  const scrollToBottom = () => {
    messagesEnd.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    
    const userMsg = { role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);
    
    try {
      const data = await chat(input, messages);
      
      if (data.message) {
        setMessages(prev => [...prev, { role: 'assistant', content: data.message }]);
      } else if (data.error) {
        setMessages(prev => [...prev, { role: 'assistant', content: 'Error: ' + data.error }]);
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Connection error: ' + e.message }]);
    }
    
    setLoading(false);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <h3>Solidify AI Chat</h3>
        <button onClick={onClose}>X</button>
      </div>
      
      <div className="chat-messages">
        {messages.length === 0 && (
          <div className="chat-welcome">
            <p>Hi! I'm Solidify, your smart contract security assistant.</p>
            <p>Ask me anything about:</p>
            <ul>
              <li>Reentrancy vulnerabilities</li>
              <li>Access control best practices</li>
              <li>ERC token security</li>
              <li>DeFi protocol risks</li>
              <li>Any security question!</li>
            </ul>
          </div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className={'chat-message ' + msg.role}>
            <span className="role">{msg.role === 'user' ? 'You' : 'Solidify'}</span>
            <div className="content">{msg.content}</div>
          </div>
        ))}
        {loading && <div className="chat-loading">Thinking...</div>}
        <div ref={messagesEnd} />
      </div>
      
      <div className="chat-input">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Ask a security question..."
          disabled={loading}
        />
        <button onClick={handleSend} disabled={loading || !input.trim()}>Send</button>
      </div>
    </div>
  );
}