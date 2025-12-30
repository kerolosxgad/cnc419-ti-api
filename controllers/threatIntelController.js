const sequelize = require("sequelize");
const { Op } = require("sequelize");
const { ThreatIndicator } = require("../models/threatIndicator");
const severityClassifier = require("../services/severityClassifier");
const threatIntelService = require("../services/threatIntel.cron");

// Search for IOCs by value, type, or source
const searchIOCs = async (req, res) => {
  try {
    const {
      query,
      type,
      source,
      severity,
      limit = 100,
      offset = 0,
      sortBy = 'lastSeen',
      sortOrder = 'DESC'
    } = req.body;

    // Build where clause
    const where = {};
    
    if (query) {
      where.value = { [Op.like]: `%${query}%` };
    }
    
    if (type) {
      where.type = type;
    }
    
    if (source) {
      where.source = { [Op.like]: `%${source}%` };
    }
    
    if (severity) {
      where.severity = severity;
    }

    // Execute query
    const { count, rows } = await ThreatIndicator.findAndCountAll({
      where,
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [[sortBy, sortOrder]],
    });

    return res.status(200).json({
      success: true,
      total: count,
      limit: parseInt(limit),
      offset: parseInt(offset),
      results: rows,
    });
  } catch (error) {
    console.error("Error searching IOCs:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Get details of a specific IOC by ID
const getIOCDetails = async (req, res) => {
  try {
    const { id } = req.body;

    const ioc = await ThreatIndicator.findByPk(id);

    if (!ioc) {
      return res.status(404).json({ 
        success: false,
        message: "IOC not found" 
      });
    }

    return res.status(200).json({
      success: true,
      ioc,
    });
  } catch (error) {
    console.error("Error getting IOC details:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Correlate IOCs - Find related indicators
const correlateIOCs = async (req, res) => {
  try {
    const { value } = req.body;

    if (!value) {
      return res.status(400).json({
        success: false,
        message: "Value parameter is required"
      });
    }

    // Find exact match
    const exactMatch = await ThreatIndicator.findOne({
      where: { value }
    });

    if (!exactMatch) {
      return res.status(404).json({ 
        success: false,
        message: "IOC not found" 
      });
    }

    // Find related IOCs
    // 1. Same source
    const sameSource = await ThreatIndicator.findAll({
      where: {
        source: exactMatch.source,
        id: { [Op.ne]: exactMatch.id }
      },
      limit: 10,
      order: [['lastSeen', 'DESC']]
    });

    // 2. Similar description keywords
    const relatedByDescription = exactMatch.description 
      ? await ThreatIndicator.findAll({
          where: {
            description: { [Op.like]: `%${exactMatch.description.split(' ')[0]}%` },
            id: { [Op.ne]: exactMatch.id }
          },
          limit: 10,
          order: [['confidence', 'DESC']]
        })
      : [];

    // 3. Same severity and type
    const sameSeverityType = await ThreatIndicator.findAll({
      where: {
        severity: exactMatch.severity,
        type: exactMatch.type,
        id: { [Op.ne]: exactMatch.id }
      },
      limit: 10,
      order: [['observedCount', 'DESC']]
    });

    return res.status(200).json({
      success: true,
      target: exactMatch,
      correlations: {
        sameSource: sameSource.length,
        sameSourceIOCs: sameSource,
        relatedByDescription: relatedByDescription.length,
        relatedByDescriptionIOCs: relatedByDescription,
        sameSeverityType: sameSeverityType.length,
        sameSeverityTypeIOCs: sameSeverityType
      }
    });
  } catch (error) {
    console.error("Error correlating IOCs:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Get IOC statistics
const getStatistics = async (req, res) => {
  try {
    // Get basic stats from service
    const basicStats = await threatIntelService.getStats();

    // Get severity breakdown
    const severityBreakdown = await ThreatIndicator.findAll({
      attributes: [
        'severity',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count']
      ],
      group: ['severity'],
      raw: true
    });

    // Get top sources
    const topSources = await ThreatIndicator.findAll({
      attributes: [
        'source',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
        [sequelize.fn('AVG', sequelize.col('confidence')), 'avgConfidence']
      ],
      group: ['source'],
      order: [[sequelize.literal('count'), 'DESC']],
      limit: 10,
      raw: true
    });

    // Get recent activity (last 24 hours)
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentActivity = await ThreatIndicator.count({
      where: {
        lastSeen: { [Op.gte]: twentyFourHoursAgo }
      }
    });

    // High severity count
    const highSeverityCount = await ThreatIndicator.count({
      where: {
        severity: { [Op.in]: ['critical', 'high'] }
      }
    });

    return res.status(200).json({
      success: true,
      statistics: {
        total: basicStats.total,
        byType: basicStats.byType,
        bySource: basicStats.bySource,
        bySeverity: severityBreakdown.reduce((acc, item) => {
          acc[item.severity] = parseInt(item.count);
          return acc;
        }, {}),
        topSources: topSources.map(s => ({
          source: s.source,
          count: parseInt(s.count),
          avgConfidence: Math.round(parseFloat(s.avgConfidence))
        })),
        recentActivity: {
          last24Hours: recentActivity
        },
        threatLevel: {
          highSeverity: highSeverityCount,
          percentage: basicStats.total > 0 
            ? Math.round((highSeverityCount / basicStats.total) * 100) 
            : 0
        }
      },
      generatedAt: new Date()
    });
  } catch (error) {
    console.error("Error getting statistics:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Generate comprehensive summary report
const getSummaryReport = async (req, res) => {
  try {
    const { timeRange } = req.query;

    // Calculate time range
    let startDate;
    const now = new Date();
    
    switch (timeRange) {
      case '24h':
        startDate = new Date(now - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        startDate = new Date(now - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
    }

    // Get all IOCs within time range (active during period)
    const recentIOCs = await ThreatIndicator.findAll({
      where: {
        lastSeen: { [Op.gte]: startDate }
      }
    });

    // Get newly created IOCs in the time range
    const newIOCs = await ThreatIndicator.count({
      where: {
        createdAt: { [Op.gte]: startDate }
      }
    });

    // Calculate severity statistics for the period
    const severityStats = recentIOCs.reduce((acc, ioc) => {
      acc[ioc.severity] = (acc[ioc.severity] || 0) + 1;
      return acc;
    }, {});

    // Get type breakdown for the period
    const typeStats = recentIOCs.reduce((acc, ioc) => {
      acc[ioc.type] = (acc[ioc.type] || 0) + 1;
      return acc;
    }, {});

    // Get source breakdown for the period
    const sourceStats = recentIOCs.reduce((acc, ioc) => {
      acc[ioc.source] = (acc[ioc.source] || 0) + 1;
      return acc;
    }, {});

    // Get top threats (critical and high severity) within the period
    const topThreats = await ThreatIndicator.findAll({
      where: {
        severity: { [Op.in]: ['critical', 'high'] },
        lastSeen: { [Op.gte]: startDate }
      },
      order: [
        ['severity', 'DESC'],
        ['confidence', 'DESC'],
        ['observedCount', 'DESC']
      ],
      limit: 20
    });

    // Calculate trends
    const criticalCount = severityStats.critical || 0;
    const highCount = severityStats.high || 0;
    const mediumCount = severityStats.medium || 0;
    const lowCount = severityStats.low || 0;
    const infoCount = severityStats.info || 0;

    const totalInPeriod = recentIOCs.length;
    const highRiskPercentage = totalInPeriod > 0 
      ? Math.round(((criticalCount + highCount) / totalInPeriod) * 100)
      : 0;

    // Get fetch status
    const fetchStatus = threatIntelService.getFetchStatus();

    return res.status(200).json({
      success: true,
      report: {
        metadata: {
          generatedAt: new Date(),
          timeRange,
          startDate,
          endDate: now
        },
        summary: {
          totalIOCs: totalInPeriod, // IOCs active/seen within the timeRange
          newInPeriod: newIOCs, // IOCs created within the timeRange
          highRiskPercentage,
          activeSources: Object.keys(sourceStats).length
        },
        severity: {
          breakdown: severityStats,
          critical: criticalCount,
          high: highCount,
          medium: mediumCount,
          low: lowCount,
          info: infoCount
        },
        types: typeStats,
        sources: sourceStats,
        topThreats: topThreats.map(t => ({
          id: t.id,
          type: t.type,
          value: t.value,
          severity: t.severity,
          confidence: t.confidence,
          source: t.source,
          description: t.description,
          observedCount: t.observedCount,
          lastSeen: t.lastSeen
        })),
        dataQuality: {
          averageConfidence: recentIOCs.length > 0
            ? Math.round(recentIOCs.reduce((sum, ioc) => sum + ioc.confidence, 0) / recentIOCs.length)
            : 0,
          multiSourceIOCs: recentIOCs.filter(ioc => ioc.observedCount > 1).length
        },
        feedStatus: {
          sources: fetchStatus.sources.filter(s => s.enabled).map(s => ({
            name: s.name,
            lastFetch: s.lastFetch,
            status: s.status,
            count: s.count
          }))
        }
      }
    });
  } catch (error) {
    console.error("Error generating summary report:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Manual trigger for IOC ingestion
const triggerIngestion = async (req, res) => {
  try {
    // This should only be accessible to admins
    console.log("[ThreatIntel] Manual ingestion triggered by user:", req.user.sub);
    
    // Run ingestion in background
    threatIntelService.ingestIOCFeeds()
      .then(() => console.log("[ThreatIntel] Manual ingestion completed"))
      .catch(err => console.error("[ThreatIntel] Manual ingestion failed:", err));

    return res.status(202).json({
      success: true,
      message: "IOC ingestion started in background"
    });
  } catch (error) {
    console.error("Error triggering ingestion:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

// Get fetch status 
const getFetchStatus = async (req, res) => {
  try {
    const status = threatIntelService.getFetchStatus();
    
    return res.status(200).json({
      success: true,
      fetchStatus: status
    });
  } catch (error) {
    console.error("Error getting fetch status:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error",
      error: error.message 
    });
  }
};

module.exports = {
  searchIOCs,
  getIOCDetails,
  correlateIOCs,
  getStatistics,
  getSummaryReport,
  triggerIngestion,
  getFetchStatus
};
