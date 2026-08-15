import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** shadcn's own class merger: clsx for conditionals, tailwind-merge so a
 *  caller's utility wins over a component's default instead of both landing
 *  in the class list and the cascade picking arbitrarily. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
