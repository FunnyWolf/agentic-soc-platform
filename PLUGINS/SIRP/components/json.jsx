function JsonViewer({ value }) {
  const rawData = value;
  let jsonData;
  let isParsingError = false;

  try {
    if (typeof rawData === 'string' && rawData.trim() !== '') {
      jsonData = JSON.parse(rawData);
    } else if (typeof rawData === 'object' && rawData !== null) {
      jsonData = rawData;
    } else {
      jsonData = null;
    }
  } catch (e) {
    isParsingError = true;
  }

  const [collapsedNodes, setCollapsedNodes] = React.useState({});

  const renderNode = (data, path = '', isLastItem = true) => {
    const renderValue = (val) => {
      const type = typeof val;
      let colorClass = 'text-gray-300';
      let displayValue = String(val);

      if (type === 'string') {
        colorClass = 'text-green-400';
        displayValue = `"${val}"`;
      } else if (type === 'number') {
        colorClass = 'text-yellow-400';
      } else if (type === 'boolean') {
        colorClass = 'text-pink-400';
      } else if (val === null) {
        colorClass = 'text-pink-400';
        displayValue = 'null';
      }

      return <span className={`font-mono ${colorClass}`}>{displayValue}</span>;
    };

    if (typeof data === 'object' && data !== null) {
      const isArray = Array.isArray(data);
      const isCollapsed = collapsedNodes[path];
      const keys = Object.keys(data);
      const hasChildren = keys.length > 0;
      const displayBrackets = keys.length === 0;

      const toggleCollapse = (e) => {
        e.stopPropagation();
        setCollapsedNodes(prev => ({
          ...prev,
          [path]: !isCollapsed
        }));
      };

      return (
        <>
          <span
            className="flex items-center space-x-1 cursor-pointer hover:bg-gray-700 rounded-sm py-1 px-1"
            onClick={toggleCollapse}
          >
            {hasChildren && (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-gray-400">
                {isCollapsed ? (
                  <path d="m9 18 6-6-6-6" />
                ) : (
                  <path d="m6 9 6 6 6-6" />
                )}
              </svg>
            )}
            <span className="text-gray-300">
              {isArray ? '[' : '{'}
            </span>
            {isCollapsed && (
              <span className="text-gray-400 italic">
                {isArray ? ` ${data.length} items` : ` ${keys.length} keys`}
                {isArray ? ']' : '}'}
              </span>
            )}
          </span>
          {!isCollapsed && hasChildren && (
            <div className={`border-l border-gray-700 pl-4 mt-1`}>
              {keys.map((key, index) => (
                <div key={key} className="flex items-baseline space-x-1">
                  <span className="text-blue-400 font-bold pr-1">
                    {isArray ? '' : `"${key}": `}
                  </span>
                  <div>
                    {renderNode(data[key], `${path}.${key}`, index === keys.length - 1)}
                  </div>
                </div>
              ))}
            </div>
          )}
          {!isCollapsed && (
            <span className="text-gray-300">
              {isArray ? ']' : '}'}
            </span>
          )}
          {!isLastItem && <span className="text-gray-300">,</span>}
        </>
      );
    }

    return (
      <span className="flex items-baseline space-x-1">
        {renderValue(data)}
        {!isLastItem && <span className="text-gray-300">,</span>}
      </span>
    );
  };

   if (!jsonData) {
    return (
      <div className="text-gray-400 p-4 font-mono bg-gray-800 rounded-lg shadow-sm">
      </div>
    );
  }
  if (isParsingError) {
    return (
      <div className="text-gray-400 p-4 font-mono bg-gray-800 rounded-lg shadow-sm">
        JSON Format Error
      </div>
    );
  }

  return (
    <div className="p-4 bg-gray-800 rounded-lg shadow-sm font-mono text-gray-300">
      {renderNode(jsonData, 'root')}
    </div>
  );
}