import Editor from '@monaco-editor/react';

export default function CodeEditor({ value, onChange, language = 'sol' }) {
  return (
    <div className="code-editor">
      <Editor
        height="400px"
        language={language}
        value={value}
        onChange={onChange}
        theme="vs-dark"
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
        }}
      />
    </div>
  );
}