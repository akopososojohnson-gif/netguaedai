# Job Application Autofill Extension

A browser extension that automatically fills job application forms on major ATS platforms (Greenhouse, Lever, Workday) using DOM heuristics.

## Features

- **Multi-Platform Support**: Works with Greenhouse, Lever, Workday, and generic job application forms
- **DOM Heuristics**: No hard-coded selectors - uses labels, placeholders, aria-labels, and input types
- **Manual Review**: Always requires user confirmation before filling forms
- **Resume Upload**: Highlights resume upload fields with instructions
- **Profile Management**: Create and manage multiple job application profiles
- **Privacy First**: All data stored locally, no cloud services

## Architecture

### Core Components

1. **Content Script** (`src/content.js`): Form detection and autofill logic
2. **Background Service** (`src/background.js`): Profile management and message coordination
3. **Platform Handlers** (`src/platforms.js`): Platform-specific form handling
4. **Popup UI** (`src/popup.js`): User interface for profile management

### Form Detection Strategy

The extension uses a multi-layered approach to detect job application forms:

1. **URL Pattern Analysis**: Identifies known ATS platforms
2. **Form Content Analysis**: Searches for job-specific keywords
3. **Field Pattern Matching**: Uses DOM heuristics to categorize fields
4. **Confidence Scoring**: Ranks forms based on multiple signals

### Field Detection Heuristics

Fields are detected using:
- Input type attributes (`type="email"`, `type="tel"`)
- Name attributes (`name="email"`, `name="first_name"`)
- ID attributes (`id="email"`, `id="resume"`)
- Placeholder text (`placeholder="Enter your email"`)
- Associated label text
- ARIA labels

## Installation

### Chrome
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the extension directory

### Firefox
1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file

## Usage

1. **Create Profile**: Click the extension icon and create a new profile with your information
2. **Navigate to Job Application**: Go to any job application page on supported platforms
3. **Trigger Autofill**: Click the extension icon and select "Autofill Form"
4. **Review and Confirm**: Review the filled fields and confirm submission

## Development

### Build
```bash
npm install
npm run build
```

### Development Mode
```bash
npm run dev
```

### Project Structure
```
job-autofill-extension/
├── manifest.json           # Extension manifest
├── popup.html             # Popup UI
├── src/
│   ├── content.js         # Content script
│   ├── background.js      # Background service worker
│   ├── popup.js           # Popup controller
│   └── platforms.js       # Platform-specific handlers
├── dist/                  # Built files
└── webpack.config.js      # Build configuration
```

## Supported Platforms

### Greenhouse
- Multi-step application forms
- Custom file upload handling
- Dynamic content support

### Lever
- Drag-and-drop resume upload
- Dynamic form sections
- Custom styling handling

### Workday
- Iframe content handling
- Complex navigation
- Multi-step processes

### Generic Forms
- Standard form field detection
- Fallback heuristics
- Custom field mapping

## Limitations

- **Resume Upload**: Cannot directly upload files due to browser security restrictions
- **Dynamic Content**: May require manual refresh on heavily dynamic pages
- **Platform Changes**: May need updates if platforms significantly change their structure

## Privacy & Security

- All data stored locally in browser storage
- No external API calls or data transmission
- Optional profile encryption support
- User-controlled data retention

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on multiple platforms
5. Submit a pull request

## License

MIT License - see LICENSE file for details