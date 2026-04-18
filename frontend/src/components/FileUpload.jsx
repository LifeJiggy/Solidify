import { useRef } from 'react';

export default function FileUpload({ onFileLoaded }) {
  const inputRef = useRef(null);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => onFileLoaded(ev.target.result);
      reader.readAsText(file);
    }
  };

  return (
    <div className="file-upload">
      <input
        ref={inputRef}
        type="file"
        accept=".sol,.js,.ts"
        onChange={handleFileChange}
        style={{ display: 'none' }}
      />
      <button onClick={() => inputRef.current?.click()}>
        Upload Contract
      </button>
    </div>
  );
}