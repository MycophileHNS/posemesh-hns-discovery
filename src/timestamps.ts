const STRICT_UTC_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

export function parseStrictUtcTimestamp(value: string): Date | undefined {
  const match = STRICT_UTC_TIMESTAMP_PATTERN.exec(value);

  if (!match) {
    return undefined;
  }

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fractionalText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const millisecond = fractionalText ? Number(fractionalText.padEnd(3, "0")) : 0;
  const parsed = new Date(Date.UTC(year, month - 1, day, hour, minute, second, millisecond));

  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day ||
    parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute ||
    parsed.getUTCSeconds() !== second ||
    parsed.getUTCMilliseconds() !== millisecond
  ) {
    return undefined;
  }

  return parsed;
}
