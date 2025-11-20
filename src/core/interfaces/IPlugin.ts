import { ScanContext } from './IScanner';
import { IDetector } from './IDetector';
import { ScanResult } from '../../types/scan-result';
import { PluginConfigSchema } from '../../types/config';

/**
 * Interface for scanner plugins
 */
export interface IScannerPlugin {
  /** Unique identifier */
  readonly id: string;

  /** Plugin name */
  readonly name: string;

  /** Plugin version */
  readonly version: string;

  /** Plugin type */
  readonly type: 'passive' | 'active' | 'hybrid';

  /** Plugin author */
  readonly author: string;

  /** Plugin description */
  readonly description: string;

  /**
   * Initialize the plugin
   * @param context Scan context
   */
  initialize(context: ScanContext): Promise<void>;

  /**
   * Execute the plugin scan
   */
  execute(): Promise<ScanResult>;

  /**
   * Cleanup plugin resources
   */
  cleanup(): Promise<void>;

  /**
   * Get plugin dependencies (other plugin IDs)
   */
  getDependencies(): string[];

  /**
   * Get configuration schema for this plugin
   */
  getConfiguration(): PluginConfigSchema;

  /**
   * Validate plugin configuration
   * @param config Configuration object
   */
  validateConfig(config: unknown): boolean;
}

/**
 * Interface for detector plugins
 */
export interface IDetectorPlugin extends IDetector {
  /** Plugin author */
  readonly author: string;

  /**
   * Get configuration schema for this detector
   */
  getConfiguration(): PluginConfigSchema;

  /**
   * Validate detector configuration
   * @param config Configuration object
   */
  validateConfig(config: unknown): boolean;
}

/**
 * Plugin metadata
 */
export interface PluginMetadata {
  /** Plugin ID */
  id: string;

  /** Plugin name */
  name: string;

  /** Plugin version */
  version: string;

  /** Plugin type */
  type: 'scanner' | 'detector' | 'reporter';

  /** Author */
  author: string;

  /** Description */
  description: string;

  /** Homepage URL */
  homepage?: string;

  /** Repository URL */
  repository?: string;

  /** License */
  license?: string;

  /** Tags for categorization */
  tags?: string[];

  /** Minimum engine version required */
  minEngineVersion?: string;

  /** Plugin dependencies */
  dependencies?: string[];
}

/**
 * Plugin loader result
 */
export interface PluginLoadResult {
  /** Whether plugin loaded successfully */
  success: boolean;

  /** Plugin metadata */
  metadata?: PluginMetadata;

  /** Error message if loading failed */
  error?: string;

  /** Plugin instance */
  instance?: IScannerPlugin | IDetectorPlugin;
}
