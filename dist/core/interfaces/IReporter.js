export class BaseReporter {
    async validateOutputPath(outputPath) {
        try {
            const fs = await import('fs/promises');
            const path = await import('path');
            const dir = path.dirname(outputPath);
            await fs.mkdir(dir, { recursive: true });
            return true;
        }
        catch (error) {
            return false;
        }
    }
    getDefaultFilename(scanId) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        return `scan-report-${scanId}-${timestamp}.${this.extension}`;
    }
    async writeFile(filePath, content) {
        const fs = await import('fs/promises');
        await this.validateOutputPath(filePath);
        await fs.writeFile(filePath, content, 'utf-8');
    }
    formatTimestamp(date) {
        return date.toISOString();
    }
    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        if (hours > 0) {
            return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
        }
        if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        }
        return `${seconds}s`;
    }
}
//# sourceMappingURL=IReporter.js.map