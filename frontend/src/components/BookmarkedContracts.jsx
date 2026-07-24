import { useState, useEffect } from 'react';
import { showToast } from './Toast';

const BOOKMARKS_KEY = 'solidify_bookmarks';

export default function BookmarkedContracts({ onSelect, currentCode }) {
  const [bookmarks, setBookmarks] = useState([]);
  const [open, setOpen] = useState(false);
  const [showAddInput, setShowAddInput] = useState(false);
  const [newName, setNewName] = useState('');

  useEffect(() => {
    try { setBookmarks(JSON.parse(localStorage.getItem(BOOKMARKS_KEY) || '[]')); }
    catch { setBookmarks([]); }
  }, [open]);

  const addBookmark = (name) => {
    try {
      const list = JSON.parse(localStorage.getItem(BOOKMARKS_KEY) || '[]');
      if (list.find(b => b.code === currentCode)) { showToast('Already bookmarked', 'info'); return; }
      list.unshift({ id: Date.now().toString(36), name: name || 'Untitled', code: currentCode, date: new Date().toISOString() });
      if (list.length > 20) list.length = 20;
      localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(list));
      setBookmarks(list);
      setShowAddInput(false);
      setNewName('');
      showToast('Contract bookmarked', 'success');
    } catch { showToast('Failed to bookmark', 'error'); }
  };

  const remove = (id) => {
    const updated = bookmarks.filter(b => b.id !== id);
    setBookmarks(updated);
    localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(updated));
    showToast('Bookmark removed', 'info');
  };

  return (
    <div className="bookmarks-wrapper">
      <button className="secondary-btn" onClick={() => setOpen(!open)}>
        Bookmarks ({bookmarks.length})
      </button>
      {open && (
        <div className="bookmarks-dropdown">
          {bookmarks.length === 0 && <p className="empty-msg">No bookmarked contracts</p>}
          {bookmarks.map(b => (
            <div key={b.id} className="bookmark-item">
              <span className="bookmark-name" onClick={() => { onSelect(b.code); setOpen(false); }}>{b.name}</span>
              <button className="bookmark-remove" onClick={() => remove(b.id)}>X</button>
            </div>
          ))}
          {currentCode && !showAddInput && (
            <button className="bookmark-add" onClick={() => setShowAddInput(true)}>+ Bookmark Current</button>
          )}
          {showAddInput && (
            <div className="bookmark-add-form">
              <input
                type="text"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                placeholder="Bookmark name..."
                onKeyDown={e => { if (e.key === 'Enter') addBookmark(newName); if (e.key === 'Escape') setShowAddInput(false); }}
                autoFocus
              />
              <button className="bookmark-add-btn" onClick={() => addBookmark(newName)}>Save</button>
              <button className="bookmark-cancel-btn" onClick={() => setShowAddInput(false)}>X</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
