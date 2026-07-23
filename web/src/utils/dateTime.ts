export type DateTimeInput = string | number | Date

const ENGLISH_LOCALE = 'en-US'

const dateTimeFormatter = new Intl.DateTimeFormat(ENGLISH_LOCALE, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZoneName: 'short',
})

const timeFormatter = new Intl.DateTimeFormat(ENGLISH_LOCALE, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
})

function validDate(value: DateTimeInput): Date | undefined {
    const parsed = value instanceof Date ? value : new Date(value)
    return Number.isNaN(parsed.getTime()) ? undefined : parsed
}

export function formatEnglishDateTime(value: DateTimeInput): string {
    const parsed = validDate(value)
    return parsed ? dateTimeFormatter.format(parsed) : ''
}

export function formatEnglishTime(value: DateTimeInput): string {
    const parsed = validDate(value)
    return parsed ? timeFormatter.format(parsed) : ''
}
