function ChatField({value, onChange, env}) {
    const userPresets = [
        {icon: 'User', color: 'bg-blue-100 text-blue-600'},
        {icon: 'Smile', color: 'bg-green-100 text-green-600'},
        {icon: 'Cat', color: 'bg-purple-100 text-purple-600'},
        {icon: 'Zap', color: 'bg-yellow-100 text-yellow-600'}
    ];
    const botPreset = {icon: 'Cpu', color: 'bg-gray-800 text-white'};

    const getInitialData = (val) => {
        try {
            if (!val) return [];
            if (Array.isArray(val)) return val;
            if (typeof val === 'string') return JSON.parse(val);
            return [];
        } catch (e) {
            return [];
        }
    };

    const [messages, setMessages] = useState(() => getInitialData(value));
    const [inputValue, setInputValue] = useState('');
    const [userIndex, setUserIndex] = useState(0);
    const scrollRef = useRef(null);

    useEffect(() => {
        setMessages(getInitialData(value));
    }, [value]);
    useEffect(() => {
        if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }, [messages]);

    const handleSend = () => {
        if (!inputValue.trim() || env.isDisabled) return;
        const currentPreset = userPresets[userIndex];
        const newMessage = {
            id: Date.now(),
            text: inputValue,
            time: new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', hour12: false}),
            sender: 'user',
            avatarIcon: currentPreset.icon,
            avatarColor: currentPreset.color
        };
        const updatedMessages = [...messages, newMessage];
        setMessages(updatedMessages);
        onChange(JSON.stringify(updatedMessages));
        setInputValue('');
    };

    const safeMessages = Array.isArray(messages) ? messages : [];

    return (
        <div className="w-4/5 h-full mx-auto font-sans flex flex-col overflow-hidden">
            <div
                className="flex flex-col h-full border border-gray-200 rounded-xl overflow-hidden bg-transparent shadow-none">
                <div className="bg-white border-b px-4 py-3 flex items-center justify-between flex-shrink-0">
                    <div className="flex items-center gap-2 text-[#151515]">
                        <LucideIcon name="MessageSquare" size="18" className="text-[#1677ff]"/>
                        <span className="font-bold text-sm">Chat History</span>
                    </div>
                    <button
                        onClick={() => {
                            setMessages([]);
                            onChange(JSON.stringify([]));
                        }}
                        disabled={env.isDisabled || safeMessages.length === 0}
                        className="p-1.5 text-gray-400 hover:text-red-500 rounded-md transition-colors disabled:opacity-30"
                    >
                        <LucideIcon name="Trash2" size="18"/>
                    </button>
                </div>

                <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-6 bg-white/40">
                    {safeMessages.length > 0 ? (
                        safeMessages.map((msg, index) => {
                            const isBot = msg.sender === 'bot';
                            return (
                                <div key={msg.id || index}
                                     className={`flex gap-3 ${isBot ? 'flex-row' : 'flex-row-reverse'}`}>
                                    <div
                                        className={`w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0 shadow-sm border border-white ${isBot ? botPreset.color : (msg.avatarColor || 'bg-blue-100')}`}>
                                        <LucideIcon name={isBot ? botPreset.icon : (msg.avatarIcon || 'User')}
                                                    size="18"/>
                                    </div>
                                    <div className={`flex flex-col ${isBot ? 'items-start' : 'items-end'} max-w-[85%]`}>
                                        <div
                                            className={`px-4 py-2.5 rounded-2xl shadow-sm text-[14px] leading-relaxed whitespace-pre-wrap break-all ${isBot ? 'bg-white border border-gray-100 text-[#333]' : 'bg-[#1677ff] text-white'}`}>
                                            {msg.text}
                                        </div>
                                        <span className="text-[10px] text-gray-400 mt-1.5 font-medium">{msg.time}</span>
                                    </div>
                                </div>
                            );
                        })
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center text-gray-300 opacity-40">
                            <LucideIcon name="Inbox" size="40" strokeWidth="1"/>
                            <p className="text-sm mt-2 italic font-medium">No records</p>
                        </div>
                    )}
                </div>

                <div className="p-4 bg-white border-t flex-shrink-0">
                    <div
                        className={`flex items-end gap-3 p-2.5 border rounded-xl transition-all ${env.isDisabled ? 'bg-gray-50' : 'bg-white focus-within:border-[#1677ff]'}`}>
                        <button
                            onClick={() => setUserIndex((prev) => (prev + 1) % 4)}
                            disabled={env.isDisabled}
                            className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 shadow-sm border border-white transition-transform active:scale-90 ${userPresets[userIndex].color}`}
                        >
                            <LucideIcon name={userPresets[userIndex].icon} size="20"/>
                        </button>
                        <textarea
                            value={inputValue}
                            onChange={(e) => setInputValue(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSend();
                                }
                            }}
                            disabled={env.isDisabled}
                            placeholder="Type message..."
                            className="flex-1 max-h-32 min-h-[36px] py-2 resize-none border-none focus:outline-none text-sm bg-transparent text-[#151515]"
                            rows={1}
                        />
                        <button
                            onClick={handleSend}
                            disabled={env.isDisabled || !inputValue.trim()}
                            className={`p-2.5 rounded-lg transition-all ${inputValue.trim() && !env.isDisabled ? 'bg-[#1677ff] text-white' : 'bg-gray-100 text-gray-400'}`}
                        >
                            <LucideIcon name="Send" size="18"/>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}