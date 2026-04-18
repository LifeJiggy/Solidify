import { useState, useRef } from 'react';

export default function FileUpload({ onFileLoaded }) {
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState('');
  const inputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    if (!file.name.endsWith('.sol')) {
      alert('Please upload a .sol file');
      return;
    }
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => onFileLoaded(e.target.result);
    reader.readAsText(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    handleFile(e.dataTransfer?.files?.[0]);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleInputChange = (e) => handleFile(e.target.files?.[0]);

  return (
    <div 
      className={'file-upload ' + (isDragging ? 'dragging' : '')}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".sol"
        onChange={handleInputChange}
        style={{ display: 'none' }}
      />
      {fileName ? (
        <div className="file-info">
          <span className="file-name">{fileName}</span>
          <button className="clear-btn" onClick={(e) => { e.stopPropagation(); setFileName(''); }}>X</button>
        </div>
      ) : (
        <div className="upload-prompt">
          <p>Drag and drop .sol file here</p>
          <span className="or">or</span>
          <button className="browse-btn">Browse Files</button>
        </div>
      )}
    </div>
  );
}